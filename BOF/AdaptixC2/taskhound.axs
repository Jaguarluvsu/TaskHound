/*
 * TaskHound AdaptixC2 AxScript Integration
 * 
 * This script registers the TaskHound BOF command with AdaptixC2.
 * It handles command registration, argument parsing, and BOF execution.
 */

// Register the taskhound command
var cmd_taskhound = ax.create_command("taskhound", "Collect scheduled tasks from remote systems", 
    "taskhound <target> [username] [password] [-save <directory>] [-unsaved-creds]", "post-exploitation");
cmd_taskhound.addArgString("target", true, "Remote system to collect from (IP or hostname)");
cmd_taskhound.addArgString("username", false, "Username for authentication");
cmd_taskhound.addArgString("password", false, "Password for authentication");
cmd_taskhound.addArgString("save_directory", false, "Directory to save XML files (use with -save flag)");
cmd_taskhound.addArgString("unsaved_creds", false, "Show tasks without stored credentials (use -unsaved-creds flag)");

// Set command hook to handle BOF execution
cmd_taskhound.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var target = parsed_json["target"];
    var username = parsed_json["username"] || "";
    var password = parsed_json["password"] || "";
    var save_dir = parsed_json["-save"] || "";
    
    // Parse command line to handle -save and -unsaved-creds flags properly
    var args = cmdline.split(/\s+/);
    var actual_username = "";
    var actual_password = "";
    var actual_save_dir = "";
    var show_unsaved_creds = false;
    
    // Parse arguments manually to handle flags
    for (var i = 1; i < args.length; i++) {
        if (args[i] === "-save" && i + 1 < args.length) {
            actual_save_dir = args[i + 1];
            i++; // Skip next argument as it's the directory
        } else if (args[i] === "-unsaved-creds") {
            show_unsaved_creds = true;
        } else if (i === 1) {
            // First argument after command is always target (already handled)
            continue;
        } else if (i === 2 && args[i] !== "-save" && args[i] !== "-unsaved-creds") {
            // Second argument is username if not a flag
            actual_username = args[i];
        } else if (i === 3 && args[i] !== "-save" && args[i] !== "-unsaved-creds") {
            // Third argument is password if not a flag
            actual_password = args[i];
        }
    }
    
    // Use parsed values
    username = actual_username;
    password = actual_password;
    save_dir = actual_save_dir;
    
    // Display execution info via console message
    ax.console_message(id, "[*] TaskHound - Remote Task Collection");
    ax.console_message(id, "[*] Target: " + target);
    
    if (username !== "") {
        ax.console_message(id, "[*] Using credentials: " + username);
    } else {
        ax.console_message(id, "[*] Using current user context");
    }
    if (save_dir !== "") {
        ax.console_message(id, "[*] Save directory: " + save_dir);
    }
    
    // Get the absolute path to the BOF file
    var bof_path = ax.script_dir() + "/taskhound.o";
    
    // Build argument buffer for BOF using proper format
    var arg_data = "";
    
    if (save_dir !== "" || show_unsaved_creds) {
        if (username !== "" && password !== "") {
            if (show_unsaved_creds) {
                // Five arguments: target, username, password, save_dir, "-unsaved-creds"
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [target, username, password, save_dir, "-unsaved-creds"]);
            } else {
                // Four arguments: target, username, password, save_dir
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr", [target, username, password, save_dir]);
            }
        } else if (username !== "") {
            if (show_unsaved_creds) {
                // Five arguments: target, username, "", save_dir, "-unsaved-creds"
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [target, username, "", save_dir, "-unsaved-creds"]);
            } else {
                // Four arguments: target, username, "", save_dir
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr", [target, username, "", save_dir]);
            }
        } else {
            if (show_unsaved_creds) {
                // Four arguments: target, "", "", save_dir, "-unsaved-creds"  
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [target, "", "", save_dir, "-unsaved-creds"]);
            } else {
                // Three arguments: target, "", "", save_dir
                arg_data = ax.bof_pack("cstr,cstr,cstr,cstr", [target, "", "", save_dir]);
            }
        }
    } else {
        if (username !== "" && password !== "") {
            // Three arguments: target, username, password
            arg_data = ax.bof_pack("cstr,cstr,cstr", [target, username, password]);
        } else if (username !== "") {
            // Two arguments: target, username
            arg_data = ax.bof_pack("cstr,cstr", [target, username]);
        } else {
            // One argument: target only
            arg_data = ax.bof_pack("cstr", [target]);
        }
    }
    
    // Execute BOF using AdaptixC2's execute bof command
    var execute_cmd = "execute bof " + bof_path;
    if (arg_data !== "") {
        execute_cmd += " " + arg_data;
    }
    
    ax.execute_alias(id, cmdline, execute_cmd);
});

// Create a command group
var cmd_group = ax.create_commands_group("TaskHound", [cmd_taskhound]);
ax.register_commands_group(cmd_group, ["beacon"], ["windows"], ["BeaconHTTP", "BeaconSMB", "BeaconTCP"]);

ax.log("[+] TaskHound BOF loaded successfully");
ax.log("[+] Use 'taskhound <target> [username] [password] [-save <directory>] [-unsaved-creds]' to collect remote tasks");
ax.log("[+] Place taskhound.o in the same directory as this script");