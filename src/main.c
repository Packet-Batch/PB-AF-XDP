#include "main.h"

struct config *cfg = NULL;

/**
 * Signal handler to shut down the program.
 * 
 * @return Void
*/
void sign_hdl(int sig)
{
    shutdown_prog(cfg);
}

/**
 * The main program.
 * 
 * @param argc The amount of arguments.
 * @param argv An array of arguments passed to program.
 * 
 * @return Int (exit code)
*/
int main(int argc, char *argv[])
{
    // Create command line structure.
    opterr = 0;
    struct cmd_line cmd = {0};

    // Parse command line and store values into cmd.
    parse_cmd_line(argc, argv, &cmd);

    // Help menu.
    if (cmd.help)
    {
        print_cmd_help();

        return EXIT_SUCCESS;
    }

    // Create AF_XDP-specific command line variable and set defaults.
    struct cmd_line_af_xdp cmd_af_xdp = {0};
    cmd_af_xdp.batch_size = 1;

    // Parse AF_XDP-specific command line.
    optind = 0;
    parse_cmd_line_af_xdp(&cmd_af_xdp, argc, argv);

    // Set global variables in AF_XDP program.
    setup_af_xdp_variables(&cmd_af_xdp, cmd.verbose);

    // Check if config is specified.
    if (cmd.config == NULL)
    {
        // Copy default values.
        cmd.config = "/etc/pcktbatch/conf.json";

        // Let us know if we're using the default config when the verbose flag is specified.
        if (cmd.verbose)
        {
            fprintf(stdout, "No config specified. Using default: %s.\n", cmd.config);
        }
    }

    // Create config structure.
    cfg = malloc(sizeof(struct config));
    memset(cfg, 0, sizeof(*cfg));

    int seq_cnt = 0;

    // Set default values on each sequence.
    for (int i = 0; i < MAX_SEQUENCES; i++)
    {
        clear_sequence(cfg, i);
    }

    // Attempt to parse config.
    u8 log = 1;

    if (cmd.cli)
    {
        fprintf(stdout, "Using command line...\n");
        log = 0;    
    }

    parse_config(cmd.config, cfg, 0, &seq_cnt, log);

    if (cmd.cli)
    {
        parse_cli(&cmd, cfg);

        // Make sure we have at least one sequence.
        if (seq_cnt < 1)
            seq_cnt = 1;
    }

    // Check for list option. If so, print helpful information for configuration.
    if (cmd.list)
    {
        print_config(cfg, seq_cnt);

        return EXIT_SUCCESS;
    }

    // Setup signals to exit the program.
    signal(SIGINT, sign_hdl);
    signal(SIGTERM, sign_hdl);

    // Loop through each sequence found.
    for (int i = 0; i < seq_cnt; i++)
    {
        seq_send(cfg->interface, cfg->seq[i], seq_cnt, cmd);

        sleep(1);
    }

    shutdown_prog(cfg);

    // Close program successfully.
    return EXIT_SUCCESS;
}