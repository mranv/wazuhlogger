#include <shared.h>
#include <os_net/os_net.h>
#include "remoted.h"
#include "state.h"

extern wnotify_t *notify;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void nb_open(netbuffer_t *buffer, int sock, const struct sockaddr_storage *peer_info)
{
    w_mutex_lock(&mutex);

    if (sock >= buffer->max_fd)
    {
        os_realloc(buffer->buffers, sizeof(sockbuffer_t) * (sock + 1), buffer->buffers);
        buffer->max_fd = sock;
        mdebug1("Extended buffer array to accommodate socket %d. New max_fd is %d.", sock, buffer->max_fd);
    }

    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));
    memcpy(&buffer->buffers[sock].peer_info, peer_info, sizeof(struct sockaddr_storage));

    buffer->buffers[sock].bqueue = bqueue_init(send_buffer_size, BQUEUE_SHRINK);

    mdebug1("Opened network buffer for socket %d.", sock);

    w_mutex_unlock(&mutex);
}

void nb_close(netbuffer_t *buffer, int sock)
{
    w_mutex_lock(&mutex);

    if (buffer->buffers[sock].bqueue)
    {
        bqueue_destroy(buffer->buffers[sock].bqueue);
        mdebug1("Destroyed buffer queue for socket %d.", sock);
    }

    os_free(buffer->buffers[sock].data);
    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));

    mdebug1("Closed network buffer for socket %d.", sock);

    w_mutex_unlock(&mutex);
}

/*
 * Receive available data from the network and push as many messages as possible
 * Returns -2 on data corruption at application layer (header).
 * Returns -1 on system call error: recv().
 * Returns 0 if no data was available in the socket.
 * Returns the number of bytes received on success.
 */
int nb_recv(netbuffer_t *buffer, int sock)
{
    long recv_len;
    unsigned long i;
    unsigned long cur_offset;
    uint32_t cur_len;

    w_mutex_lock(&mutex);

    sockbuffer_t *sockbuf = &buffer->buffers[sock];
    unsigned long data_ext = sockbuf->data_len + receive_chunk;

    // Extend data buffer
    if (data_ext > sockbuf->data_size)
    {
        os_realloc(sockbuf->data, data_ext, sockbuf->data);
        sockbuf->data_size = data_ext;
        mdebug1("Extended data buffer for socket %d to size %lu.", sock, data_ext);
    }

    // Receive and append
    recv_len = recv(sock, sockbuf->data + sockbuf->data_len, receive_chunk, 0);

    if (recv_len <= 0)
    {
        mdebug1("Receive failed for socket %d: %s (%ld).", sock, strerror(errno), recv_len);
        goto end;
    }

    sockbuf->data_len += recv_len;
    mdebug1("Received %ld bytes from socket %d.", recv_len, sock);

    // Dispatch as many messages as possible
    for (i = 0; i + sizeof(uint32_t) <= sockbuf->data_len; i = cur_offset + cur_len)
    {
        cur_len = wnet_order(*(uint32_t *)(sockbuf->data + i));

        if (cur_len > OS_MAXSTR)
        {
            char hex[OS_SIZE_2048 + 1] = {0};
            print_hex_string(&sockbuf->data[i], sockbuf->data_len - i, hex, sizeof(hex));
            mwarn("Unexpected message (hex): '%s'", hex);
            recv_len = -2;
            goto end;
        }

        cur_offset = i + sizeof(uint32_t);

        if (cur_offset + cur_len > sockbuf->data_len)
        {
            mdebug1("Incomplete message detected. Only processing partial data for socket %d.", sock);
            break;
        }

        rem_msgpush(sockbuf->data + cur_offset, cur_len, &sockbuf->peer_info, sock);
        mdebug1("Dispatched message of size %u bytes from socket %d.", cur_len, sock);
    }

    // Move remaining data to the start
    if (i > 0)
    {
        if (i < sockbuf->data_len)
        {
            memcpy(sockbuf->data, sockbuf->data + i, sockbuf->data_len - i);
            mdebug1("Moved remaining %lu bytes to start of buffer for socket %d.", sockbuf->data_len - i, sock);
        }

        sockbuf->data_len -= i;

        switch (buffer_relax)
        {
        case 0:
            // Do not deallocate memory.
            break;

        case 1:
            // Shrink memory to fit the current buffer or the receive chunk.
            sockbuf->data_size = sockbuf->data_len > receive_chunk ? sockbuf->data_len : receive_chunk;
            os_realloc(sockbuf->data, sockbuf->data_size, sockbuf->data);
            mdebug1("Shrunk buffer to %lu bytes for socket %d.", sockbuf->data_size, sock);
            break;

        default:
            // Full memory deallocation.
            sockbuf->data_size = sockbuf->data_len;

            if (sockbuf->data_size)
            {
                os_realloc(sockbuf->data, sockbuf->data_size, sockbuf->data);
                mdebug1("Deallocated buffer to fit %lu bytes for socket %d.", sockbuf->data_size, sock);
            }
            else
            {
                os_free(sockbuf->data);
                mdebug1("Freed buffer for socket %d.", sock);
            }
        }
    }

end:

    w_mutex_unlock(&mutex);
    return recv_len;
}

int nb_send(netbuffer_t *buffer, int socket)
{
    ssize_t sent_bytes = 0;

    char data[send_chunk];
    memset(data, 0, send_chunk);

    w_mutex_lock(&mutex);

    if (buffer->buffers[socket].bqueue)
    {
        ssize_t peeked_bytes = bqueue_peek(buffer->buffers[socket].bqueue, data, send_chunk, BQUEUE_NOFLAG);
        if (peeked_bytes > 0)
        {
            // Asynchronous sending
            sent_bytes = send(socket, (const void *)data, peeked_bytes, MSG_DONTWAIT);
            mdebug1("Sent %zd bytes to socket %d.", sent_bytes, socket);
        }

        if (sent_bytes > 0)
        {
            bqueue_drop(buffer->buffers[socket].bqueue, sent_bytes);
        }
        else if (sent_bytes < 0)
        {
            switch (errno)
            {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                mdebug1("Send to socket %d would block, retrying...", socket);
                break;
            default:
                merror("Could not send data to socket %d: %s (%d)", socket, strerror(errno), errno);
            }
        }

        if (!peeked_bytes || bqueue_used(buffer->buffers[socket].bqueue) == 0)
        {
            wnotify_modify(notify, socket, WO_READ);
        }
    }

    w_mutex_unlock(&mutex);

    return sent_bytes;
}

int nb_queue(netbuffer_t *buffer, int socket, char *crypt_msg, ssize_t msg_size, char *agent_id)
{
    int retval = -1;
    int header_size = sizeof(uint32_t);
    char data[msg_size + header_size];
    const uint32_t bytes = wnet_order(msg_size);

    memcpy((data + header_size), crypt_msg, msg_size);
    // Add header at the beginning, first 4 bytes, it is message msg_size
    memcpy(data, &bytes, header_size);

    w_mutex_lock(&mutex);
    mdebug2("Entering nb_queue: socket=%d, msg_size=%zu", socket, msg_size);

    if (buffer->buffers[socket].bqueue)
    {
        mdebug2("Buffer queue exists for socket %d: buffer_size=%lu, current_used=%lu",
                socket,
                buffer->buffers[socket].bqueue->max_length,
                buffer->buffers[socket].bqueue->length);

        if (!bqueue_push(buffer->buffers[socket].bqueue, (const void *)data, (size_t)(msg_size + header_size), BQUEUE_NOFLAG))
        {
            mdebug2("Initial queue push failed for socket %d: buffer_size=%lu, used=%lu, msg_size=%lu",
                    socket,
                    buffer->buffers[socket].bqueue->max_length,
                    buffer->buffers[socket].bqueue->length,
                    msg_size);

            if (bqueue_used(buffer->buffers[socket].bqueue) == (size_t)(msg_size + header_size))
            {
                mdebug2("Buffer size adequate after retry for socket %d: buffer_size=%lu, used=%lu",
                        socket,
                        buffer->buffers[socket].bqueue->max_length,
                        buffer->buffers[socket].bqueue->length);

                wnotify_modify(notify, socket, (WO_READ | WO_WRITE));
            }
            retval = 0;
        }
        else
        {
            mdebug2("Not enough buffer space for socket %d. Retrying... [buffer_size=%lu, used=%lu, msg_size=%lu]",
                    socket,
                    buffer->buffers[socket].bqueue->max_length,
                    buffer->buffers[socket].bqueue->length,
                    msg_size);

            w_mutex_unlock(&mutex);
            sleep(send_timeout_to_retry);
            w_mutex_lock(&mutex);

            if (buffer->buffers[socket].bqueue)
            {
                if (!bqueue_push(buffer->buffers[socket].bqueue, (const void *)data, (size_t)(msg_size + header_size), BQUEUE_NOFLAG))
                {
                    mdebug2("Retry push successful for socket %d: buffer_size=%lu, used=%lu, msg_size=%lu",
                            socket,
                            buffer->buffers[socket].bqueue->max_length,
                            buffer->buffers[socket].bqueue->length,
                            msg_size);

                    if (bqueue_used(buffer->buffers[socket].bqueue) == (size_t)(msg_size + header_size))
                    {
                        wnotify_modify(notify, socket, (WO_READ | WO_WRITE));
                    }
                    retval = 0;
                }
                else
                {
                    mdebug2("Retry push failed for socket %d: buffer_size=%lu, used=%lu, msg_size=%lu",
                            socket,
                            buffer->buffers[socket].bqueue->max_length,
                            buffer->buffers[socket].bqueue->length,
                            msg_size);
                }
            }
        }
    }

    w_mutex_unlock(&mutex);

    if (retval < 0)
    {
        rem_inc_send_discarded(agent_id);
        mwarn("Package dropped. Could not append data into buffer.");
    }

    return retval;
}
