/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "shared_download.h"
#include <pthread.h>

OSHash *ptable;
static remote_files_group *agent_remote_group;
static char yaml_file[OS_SIZE_1024 + 1];
static time_t yaml_file_date;
static ino_t yaml_file_inode;
static pthread_mutex_t rem_yaml_mutex = PTHREAD_MUTEX_INITIALIZER;

remote_files_group *w_parser_get_group(const char *name)
{
    remote_files_group *group = NULL;

    w_mutex_lock(&rem_yaml_mutex);

    if (ptable)
    {
        group = OSHash_Get(ptable, name);
        if (group)
        {
            mdebug1("anubhav-sd, Group '%s' found in hash table.", name);
        }
        else
        {
            mdebug1("anubhav-sd, Group '%s' not found in hash table.", name);
        }
    }
    else
    {
        mdebug1("anubhav-sd, Hash table is NULL, unable to find group '%s'.", name);
    }

    w_mutex_unlock(&rem_yaml_mutex);
    return group;
}

void w_yaml_create_groups()
{
    int i;

    if (agent_remote_group)
    {
        for (i = 0; agent_remote_group[i].name; i++)
        {
            mdebug1("anubhav-sd, Creating group '%s'.", agent_remote_group[i].name);
            w_create_group(agent_remote_group[i].name);
        }
    }
    else
    {
        mdebug1("anubhav-sd, No agent remote group defined, no groups created.");
    }
}

const char *w_read_scalar_value(yaml_event_t *event)
{
    return (const char *)event->data.scalar.value;
}

int w_move_next(yaml_parser_t *parser, yaml_event_t *event)
{
    if (!yaml_parser_parse(parser, event))
    {
        merror("anubhav-sd, Parser error on line %d: [(%d)-(%s)]", (unsigned int)parser->problem_mark.line, parser->error, parser->problem);
        return W_PARSER_ERROR;
    }
    return 0;
}

int w_read_group(yaml_parser_t *parser, remote_files_group *group)
{
    yaml_event_t event;
    int i;

    // Load default values
    group->merge_file_index = -1;
    group->poll = 1800;

    mdebug1("anubhav-sd, Reading group configuration.");

    if (w_move_next(parser, &event))
    {
        goto error;
    }

    switch (event.type)
    {
    case YAML_MAPPING_START_EVENT:
        do
        {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event))
            {
                goto error;
            }

            switch (event.type)
            {
            case YAML_SCALAR_EVENT:
                if (!strcmp(w_read_scalar_value(&event), "files"))
                {

                    mdebug1("anubhav-sd, Reading files configuration.");

                    // Read group files
                    if (group->files = w_read_group_files(parser), !group->files)
                    {
                        goto error;
                    }

                    // Check if the file name is merged.mg
                    for (i = 0; group->files[i].name; i++)
                    {
                        if (!strcmp(group->files[i].name, SHAREDCFG_FILENAME))
                        {
                            group->merge_file_index = i;
                            mdebug1("anubhav-sd, Merge file found at index %d.", i);
                            break;
                        }
                    }
                }
                else if (!strcmp(w_read_scalar_value(&event), "poll"))
                {
                    yaml_event_delete(&event);

                    // Read group poll
                    if (w_move_next(parser, &event))
                    {
                        goto error;
                    }

                    if (event.type != YAML_SCALAR_EVENT)
                    {
                        merror(W_PARSER_ERROR_EXPECTED_VALUE, "poll");
                        goto error;
                    }

                    char *end;
                    if (group->poll = strtol(w_read_scalar_value(&event), &end, 10), *end || group->poll < 0)
                    {
                        merror(W_PARSER_POLL, w_read_scalar_value(&event));
                        goto error;
                    }

                    mdebug1("anubhav-sd, Poll value set to %d.", group->poll);
                }
                break;

            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
                goto error;
            }
        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return 0;

    default:
        merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
    }

error:
    yaml_event_delete(&event);
    return -1;
}

remote_files_group *w_read_groups(yaml_parser_t *parser)
{
    remote_files_group *groups;
    yaml_event_t event;
    int index = 0;

    os_calloc(1, sizeof(remote_files_group), groups);

    mdebug1("anubhav-sd, Reading groups.");

    if (w_move_next(parser, &event))
    {
        goto error;
    }

    switch (event.type)
    {
    case YAML_MAPPING_START_EVENT:
        do
        {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event))
            {
                goto error;
            }

            switch (event.type)
            {
            case YAML_SCALAR_EVENT:
                os_realloc(groups, sizeof(remote_files_group) * (index + 2), groups);
                memset(groups + index + 1, 0, sizeof(remote_files_group));
                os_strdup(w_read_scalar_value(&event), groups[index].name);

                mdebug1("anubhav-sd, Reading configuration for group '%s'.", groups[index].name);

                if (w_read_group(parser, groups + index) < 0)
                {
                    goto error;
                }

                index++;
                break;

            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
                goto error;
            }
        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return groups;

    default:
        merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
    }

error:
    if (groups)
    {
        free(groups);
        groups = NULL;
    }
    yaml_event_delete(&event);
    return NULL;
}

file *w_read_group_files(yaml_parser_t *parser)
{
    file *files;
    yaml_event_t event;
    int index = 0;

    os_calloc(1, sizeof(file), files);

    mdebug1("anubhav-sd, Reading group files.");

    if (w_move_next(parser, &event))
    {
        goto error;
    }

    switch (event.type)
    {
    case YAML_MAPPING_START_EVENT:
        do
        {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event))
            {
                goto error;
            }

            switch (event.type)
            {
            case YAML_SCALAR_EVENT:
                os_realloc(files, sizeof(file) * (index + 2), files);
                memset(files + index + 1, 0, sizeof(file));
                os_strdup(w_read_scalar_value(&event), files[index].name);

                mdebug1("anubhav-sd, File '%s' found.", files[index].name);

                yaml_event_delete(&event);

                if (!(yaml_parser_parse(parser, &event) && event.type == YAML_SCALAR_EVENT))
                {
                    merror(W_PARSER_ERROR_EXPECTED_VALUE, files[index].name);
                    goto error;
                }

                os_strdup(w_read_scalar_value(&event), files[index].url);
                index++;
                break;
            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
                goto error;
            }
        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return files;

    default:
        merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
        goto error;
    }

error:
    if (files)
    {
        int i;
        for (i = 0; files[i].name; i++)
        {
            free(files[i].url);
            free(files[i].name);
        }

        free(files);
        files = NULL;
    }
    yaml_event_delete(&event);
    return NULL;
}

int w_do_parsing(const char *yaml_file, remote_files_group **agent_remote_group)
{
    FILE *fh = fopen(yaml_file, "r");
    yaml_parser_t parser;
    yaml_event_t event;
    int retval = W_PARSER_ERROR;

    *agent_remote_group = NULL;

    if (fh == NULL)
    {
        merror(W_PARSER_ERROR_FILE, yaml_file);
        return OS_FILERR;
    }

    if (!yaml_parser_initialize(&parser))
    {
        merror(W_PARSER_ERROR_INIT);
        fclose(fh);
        return OS_INVALID;
    }

    mdebug1("anubhav-sd, Parsing YAML file '%s'.", yaml_file);

    yaml_parser_set_input_file(&parser, fh);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_STREAM_START_EVENT))
    {
        merror("anubhav-sd, Parser error %d: expecting file begin", parser.error);
        goto end;
    }

    yaml_event_delete(&event);

    if (!yaml_parser_parse(&parser, &event))
    {
        merror("anubhav-sd, Parser error on line %d: [(%d)-(%s)]", (unsigned int)parser.problem_mark.line, parser.error, parser.problem);
        goto end;
    }

    switch (event.type)
    {
    case YAML_DOCUMENT_START_EVENT:
        yaml_event_delete(&event);

        if (w_move_next(&parser, &event))
        {
            goto end;
        }

        switch (event.type)
        {
        case YAML_MAPPING_START_EVENT:
            do
            {
                yaml_event_delete(&event);

                if (w_move_next(&parser, &event))
                {
                    goto end;
                }

                switch (event.type)
                {
                case YAML_SCALAR_EVENT:
                    // Read groups
                    if (!strcmp(w_read_scalar_value(&event), "groups"))
                    {
                        if (*agent_remote_group)
                        {
                            mwarn("anubhav-sd, Parsing '%s': redefinition of 'group'. Ignoring repeated sections", yaml_file);
                        }
                        else
                        {
                            if (!(*agent_remote_group = w_read_groups(&parser)))
                            {
                                goto end;
                            }
                        }
                    }
                    else
                    {
                        merror("anubhav-sd, Parsing file '%s': unexpected identifier: '%s' on line %d", yaml_file, w_read_scalar_value(&event), (unsigned int)event.start_mark.line);
                    }

                    break;
                case YAML_MAPPING_END_EVENT:
                    break;

                default:
                    merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
                    goto end;
                }
            } while (event.type != YAML_MAPPING_END_EVENT);
            break;

        default:
            merror("anubhav-sd, Parsing error on line %d: unexpected token", (unsigned int)event.start_mark.line);
            goto end;
        }

        break;

    default:
        mwarn("anubhav-sd, Parsing '%s': file empty", yaml_file);
    }

    yaml_event_delete(&event);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_DOCUMENT_END_EVENT))
    {
        merror("anubhav-sd, Parser error on line %d: [(%d)-(expecting document end)]", (unsigned int)parser.problem_mark.line, parser.error);
        goto end;
    }

    yaml_event_delete(&event);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_STREAM_END_EVENT))
    {
        merror("anubhav-sd, Parser error on line %d: [(%d)-(expecting file end on line)]", (unsigned int)parser.problem_mark.line, parser.error);
        goto end;
    }

    retval = 1;

end:
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fh);
    return retval;
}

void w_free_groups()
{
    int i = 0;

    if (agent_remote_group)
    {
        for (i = 0; agent_remote_group[i].name; i++)
        {
            int j = 0;
            if (agent_remote_group[i].files)
            {
                for (j = 0; agent_remote_group[i].files[j].name; j++)
                {
                    free(agent_remote_group[i].files[j].url);
                    free(agent_remote_group[i].files[j].name);
                }
                free(agent_remote_group[i].files);
            }
            free(agent_remote_group[i].name);
        }

        free(agent_remote_group);
        agent_remote_group = NULL;
        mdebug1("anubhav-sd, Freed agent remote group memory.");
    }

    if (ptable)
    {
        OSHash_Free(ptable);
        ptable = NULL;
        mdebug1("anubhav-sd, Freed hash table memory.");
    }
}

int w_yaml_file_has_changed()
{
    int changed = (yaml_file_date != File_DateofChange(yaml_file) || yaml_file_inode != File_Inode(yaml_file));
    mdebug1("anubhav-sd, YAML file changed status: %d.", changed);
    return changed;
}

int w_yaml_file_update_structs()
{
    mdebug1("anubhav-sd, Updating YAML file structures.");

    minfo(W_PARSER_FILE_CHANGED, yaml_file);
    w_mutex_lock(&rem_yaml_mutex);
    w_free_groups();

    if (ptable = OSHash_Create(), !ptable)
    {
        w_mutex_unlock(&rem_yaml_mutex);
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    w_prepare_parsing();
    w_mutex_unlock(&rem_yaml_mutex);
    return 0;
}

void w_create_group(char *group)
{
    char group_path[PATH_MAX] = {0};

    if (snprintf(group_path, PATH_MAX, "%s/%s", SHAREDCFG_DIR, group) >= PATH_MAX)
    {
        mwarn(W_PARSER_GROUP_TOO_LARGE, PATH_MAX);
    }
    else
    {
        /* Check if group exists */
        DIR *group_dir = opendir(group_path);

        if (!group_dir)
        {
            /* Create the group */
            if (mkdir(group_path, 0770) < 0)
            {
                switch (errno)
                {
                case EEXIST:
                    if (IsDir(group_path) < 0)
                    {
                        merror("anubhav-sd, Couldn't make dir '%s': not a directory.", group_path);
                    }
                    break;

                case EISDIR:
                    break;

                default:
                    merror("anubhav-sd, Couldn't make dir '%s': %s", group_path, strerror(errno));
                    break;
                }
            }
            else
            {
                if (chmod(group_path, 0770) < 0)
                {
                    merror("anubhav-sd, Error in chmod setting permissions for path: %s", group_path);
                }
            }
        }
        else
        {
            closedir(group_dir);
            mdebug1("anubhav-sd, Group directory '%s' already exists.", group_path);
        }
    }
}

/* Parse files.yml file
 * Return 1 on parse success.
 * Return 0 if no parse was performed (missing file).
 * Return -1 on parse error.
 */
int w_prepare_parsing()
{
    int parse_ok;

    // Save date and inode of the yaml file
    yaml_file_inode = File_Inode(yaml_file);
    yaml_file_date = File_DateofChange(yaml_file);

    mdebug1("anubhav-sd, Preparing parsing. File inode: %ld, date: %ld", (long)yaml_file_inode, (long)yaml_file_date);

    if (yaml_file_inode != (ino_t)-1 && yaml_file_date != -1)
    {
        if ((parse_ok = w_do_parsing(yaml_file, &agent_remote_group)) == 1)
        {
            int i = 0;

            minfo(W_PARSER_SUCCESS, yaml_file);

            // Add the groups
            if (agent_remote_group)
            {
                for (i = 0; agent_remote_group[i].name; i++)
                {
                    OSHash_Add(ptable, agent_remote_group[i].name, &agent_remote_group[i]);
                    mdebug1("anubhav-sd, Added group '%s' to hash table.", agent_remote_group[i].name);
                }
            }

            return 1;
        }
        else
        {
            merror("anubhav-sd, Parsing failed for file '%s'.", yaml_file);
            return -1;
        }
    }
    else
    {
        mdebug1("anubhav-sd, Shared configuration file not found.");
        w_free_groups();
        return 0;
    }
}

int w_init_shared_download()
{
    agent_remote_group = NULL;

    if (ptable = OSHash_Create(), !ptable)
    {
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    snprintf(yaml_file, OS_SIZE_1024, "%s/%s", SHAREDCFG_DIR, W_SHARED_YAML_FILE);
    mdebug1("anubhav-sd, Initializing shared download with YAML file '%s'.", yaml_file);

    if (w_prepare_parsing() == 1)
    {
        /* Check download module connection */
        int i;

        for (i = SOCK_ATTEMPTS; i > 0; --i)
        {
            if (wurl_check_connection() == 0)
            {
                mdebug1("anubhav-sd, Download module connection established.");
                break;
            }
            else
            {
                mdebug2("anubhav-sd, Download module not yet available. Remaining attempts: %d", i - 1);
                sleep(1);
            }
        }

        if (i == 0)
        {
            merror("anubhav-sd, Cannot connect to the download module socket. External shared file download is not available.");
        }
    }

    return 0;
}
