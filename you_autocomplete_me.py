#!/usr/bin/env python3

import os
import sys
import re
import argparse
import subprocess
import magic
import tempfile
import concurrent.futures
from pathlib import Path
import time
import shutil
import string
import json
import logging
from typing import Set, Dict, List, Tuple, Optional, Any
import gzip

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("you_autocomplete_me")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Scan executables for CLI arguments to generate bash autocompletions')
    parser.add_argument('directories', type=str, nargs='*', help='Directories containing executables to scan (use $PATH to scan all directories in PATH)')
    parser.add_argument('-o', '--output', type=str, help='Output file for bash completion script (defaults to ~/.bash_completion.d/auto_completions.sh)')
    parser.add_argument('--new', action='store_true', help='Erase old completions instead of merging')
    parser.add_argument('--scan-path', action='store_true', help='Scan all directories in PATH')
    parser.add_argument('--fix', action='store_true', help='Fix existing completion script without scanning for new completions')
    parser.add_argument('-j', '--jobs', type=int, default=os.cpu_count(), help='Number of parallel jobs (default: number of CPU cores)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--scan-manpages', action='store_true', help='Scan man pages for additional arguments')
    parser.add_argument('--scan-help', action='store_true', help='Try to parse --help output (requires running binaries)')
    parser.add_argument('--cache', action='store_true', help='Cache extracted arguments between runs')
    parser.add_argument('--cache-file', type=str, default='~/.cache/you_autocomplete_me/cache.json', help='Cache file location')
    parser.add_argument('--min-confidence', type=int, default=1, help='Minimum confidence level to include an argument (1-10)')
    return parser.parse_args()

def is_executable(filepath):
    return os.access(filepath, os.X_OK)

def get_file_type(filepath):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(filepath)
    return file_type

def extract_shebang(filepath):
    """Extract the shebang from a script file."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            first_line = f.readline().strip()
            if first_line.startswith('#!'):
                return first_line[2:].strip()
    except:
        pass
    return None

def find_man_page(command_name):
    """Find the man page for a given command."""
    try:
        # Try to find the man page
        manpath = subprocess.check_output(['manpath'], text=True).strip()
        man_dirs = manpath.split(':')
        
        # Look in standard man locations
        for man_dir in man_dirs:
            for section in ['1', '8']:  # Most commands are in sections 1 and 8
                # Check compressed and uncompressed man pages
                candidates = [
                    os.path.join(man_dir, f'man{section}', f'{command_name}.{section}'),
                    os.path.join(man_dir, f'man{section}', f'{command_name}.{section}.gz'),
                ]
                
                for candidate in candidates:
                    if os.path.exists(candidate):
                        return candidate
    except:
        pass
    
    return None

def extract_args_from_man_page(man_page_path: str) -> Set[str]:
    """Extract command line arguments from a man page."""
    args = set()
    
    try:
        # Handle gzipped man pages
        if man_page_path.endswith('.gz'):
            with gzip.open(man_page_path, 'rt', errors='ignore') as f:
                content = f.read()
        else:
            with open(man_page_path, 'r', errors='ignore') as f:
                content = f.read()
        
        # Look for OPTIONS or PARAMETERS sections in the man page
        section_matches = re.finditer(r'\.SH (?:OPTIONS|PARAMETERS)(?:\n|.)*?(?:\n\.SH|\Z)', 
                                       content, re.MULTILINE | re.DOTALL)
        
        for section_match in section_matches:
            section_text = section_match.group(0)
            
            # Look for option patterns like '.TP\n.B -x, --option'
            option_patterns = [
                r'\.(?:TP|IP|PP|B|I)\n\.(?:B|I)\s+(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+)(?:,\s*(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+))?',
                r'\.(?:TP|IP|PP)\n(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+)(?:,\s*(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+))?',
                r'\\fB(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+)\\fR',
                r'\.B\s+(-{1,2}[a-zA-Z0-9][-a-zA-Z0-9_]+)'
            ]
            
            for pattern in option_patterns:
                matches = re.finditer(pattern, section_text)
                for match in matches:
                    # Add each group that starts with - or --
                    for i in range(1, len(match.groups()) + 1):
                        if match.group(i) and match.group(i).startswith('-'):
                            # Extract just the option part, not any arguments it might take
                            option = match.group(i).split()[0].split('=')[0].rstrip(',;:')
                            args.add(option)
    except Exception as e:
        logger.debug(f"Error extracting args from man page {man_page_path}: {e}")
    
    return args

def extract_args_from_python_script(filepath: Path) -> Set[str]:
    """Extract arguments from Python scripts using advanced patterns."""
    args = set()
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Pattern 1: Standard argparse patterns
        arg_matches = re.finditer(r'(?:add_argument|add_option)\(\s*(?:\'|")(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)(?:\'|")', content)
        for match in arg_matches:
            args.add(match.group(1))
        
        # Pattern 2: Multiple arguments added in one call
        multi_args = re.finditer(r'(?:add_argument|add_option)\(\s*\[\s*(?:\'|")(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', content)
        for match in multi_args:
            args.add(match.group(1))
        
        # Pattern 3: Short/long form paired arguments
        paired_args = re.finditer(r'(?:add_argument|add_option)\(\s*(?:\'|")(-[a-zA-Z0-9])(?:\'|")\s*,\s*(?:\'|")(--[a-zA-Z0-9][a-zA-Z0-9_-]*)(?:\'|")', content)
        for match in paired_args:
            args.add(match.group(1))
            args.add(match.group(2))
        
        # Pattern 4: argparse ArgumentParser with explicitly defined arguments
        parser_decl = re.finditer(r'ArgumentParser\(.*?description=["\']([^"\']+)["\']', content)
        for match in parser_decl:
            desc = match.group(1).lower()
            # If the description mentions arguments, try to extract them from phrases like "use -x to..."
            if any(kw in desc for kw in ['option', 'arg', 'flag', 'parameter']):
                desc_args = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', desc)
                for arg_match in desc_args:
                    args.add(arg_match.group(1))
        
        # Pattern 5: Click library pattern
        click_patterns = [
            r'@click\.(?:option|argument)\([\'"](-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)[\'"]',
            r'click\.(?:option|argument)\([\'"](-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)[\'"]',
        ]
        
        for pattern in click_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                args.add(match.group(1))
        
        # Pattern 6: Fire library (inference)
        if 'import fire' in content or 'from fire import' in content:
            # Look for class methods that might be exposed as commands
            class_methods = re.finditer(r'class\s+([A-Za-z0-9_]+).*?:.*?def\s+([a-zA-Z0-9_]+)', content, re.DOTALL)
            for match in class_methods:
                # Fire converts methods to commands with dashes
                method_name = match.group(2)
                if not method_name.startswith('_'):  # Skip private methods
                    args.add(f'--{method_name.replace("_", "-")}')
        
        # Pattern 7: docopt patterns
        if 'import docopt' in content or 'from docopt import' in content:
            # Look for docopt style documentation
            docopt_patterns = re.finditer(r'"""(.*?)(?:Options|Arguments):(.*?)"""', content, re.DOTALL)
            for match in docopt_patterns:
                usage = match.group(1)
                options = match.group(2)
                
                # Extract arguments from the usage pattern
                usage_args = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', usage)
                for arg_match in usage_args:
                    args.add(arg_match.group(1))
                
                # Extract arguments from the options section
                options_args = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', options)
                for arg_match in options_args:
                    args.add(arg_match.group(1))
    
    except Exception as e:
        logger.debug(f"Error extracting args from Python script {filepath}: {e}")
    
    return args

def extract_args_from_shell_script(filepath: Path) -> Set[str]:
    """Extract arguments from shell scripts using advanced patterns."""
    args = set()
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Pattern 1: getopts pattern
        getopts_matches = re.finditer(r'getopts\s+["\']([a-zA-Z0-9:]+)["\']', content)
        for match in getopts_matches:
            # getopts uses single letters with : for required arguments
            opts = match.group(1).replace(':', '')
            for opt in opts:
                args.add(f'-{opt}')
        
        # Pattern 2: case statement with dash options
        case_blocks = re.finditer(r'case\s+(?:\$[12\{\}a-zA-Z0-9_]*|\$\@|\"\$\@\")\s+in(.*?)esac', content, re.DOTALL)
        for case_block in case_blocks:
            case_content = case_block.group(1)
            # Look for patterns like "-h|--help)"
            option_patterns = re.finditer(r'([\'"]?-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*[\'"]?)(\s*\|\s*[\'"]?-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*[\'"]?)*\s*\)', case_content)
            
            for opt_match in option_patterns:
                full_pattern = opt_match.group(0)
                # Split by | to get all alternatives
                alternatives = re.split(r'\s*\|\s*', full_pattern.strip()[:-1])
                for alt in alternatives:
                    # Clean up any quotes
                    cleaned = alt.strip('"\'')
                    if cleaned.startswith('-'):
                        args.add(cleaned)
        
        # Pattern 3: Help/usage text in comments
        help_comments = re.finditer(r'#\s*(?:Usage|Help):[^\n]*\n(?:#[^\n]*\n)+', content)
        for help_block in help_comments:
            help_text = help_block.group(0)
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', help_text)
            for match in opt_matches:
                args.add(match.group(1))
        
        # Pattern 4: Analyzing parameter parsing in functions
        param_checks = re.finditer(r'if\s+\[\s+"\$[0-9]"\s+=\s+"(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)"\s+\]', content)
        for match in param_checks:
            args.add(match.group(1))
        
        # Pattern 5: Explicit flag checks
        flag_checks = re.finditer(r'(?:until|while|if)\s+(?:.*?\s+)?\[\s+.[^]]*?(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)[^]]*?\]', content)
        for match in flag_checks:
            candidate = match.group(1)
            # Filter out variable references and expressions
            if not (candidate.startswith('$') or candidate == '--'):
                args.add(candidate)
        
        # Pattern 6: Advanced parameter handling
        shift_patterns = re.finditer(r'(?:case|if).*?(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*).*?shift', content)
        for match in shift_patterns:
            args.add(match.group(1))
        
        # Pattern 7: getopt usage
        getopt_patterns = re.finditer(r'getopt\s+(?:-o\s+([a-zA-Z0-9:]+))?(?:\s+--long\s+([a-zA-Z0-9_,-:]+))?', content)
        for match in getopt_patterns:
            # Short options
            if match.group(1):
                short_opts = match.group(1).replace(':', '')
                for opt in short_opts:
                    args.add(f'-{opt}')
            
            # Long options
            if match.group(2):
                long_opts = match.group(2).split(',')
                for opt in long_opts:
                    # Remove parameter indicator
                    clean_opt = opt.split(':')[0].strip()
                    args.add(f'--{clean_opt}')
    
    except Exception as e:
        logger.debug(f"Error extracting args from shell script {filepath}: {e}")
    
    return args

def extract_args_from_c_cpp_code(filepath: Path) -> Set[str]:
    """Extract arguments from C/C++ source code."""
    args = set()
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Pattern 1: getopt and getopt_long patterns
        getopt_patterns = re.finditer(r'getopt(?:_long)?\s*\(\s*argc\s*,\s*argv\s*,\s*["\']([a-zA-Z0-9:+]+)["\']', content)
        for match in getopt_patterns:
            short_opts = match.group(1).replace(':', '').replace('+', '')
            for opt in short_opts:
                args.add(f'-{opt}')
        
        # Pattern 2: getopt_long with long options
        getopt_long_arrays = re.finditer(r'(?:static\s+)?(?:struct\s+)?(?:option|option_t)\s+(\w+)\s*\[\s*\]\s*=\s*\{([^}]+)\}', content)
        for match in getopt_long_arrays:
            array_content = match.group(2)
            # Look for entries like {"help", no_argument, 0, 'h'}
            entries = re.finditer(r'\{\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']', array_content)
            for entry in entries:
                long_opt = entry.group(1)
                if long_opt and long_opt not in ['NULL', '0', 'null']:
                    args.add(f'--{long_opt}')
        
        # Pattern 3: Looking for argument parsing in if conditions
        arg_compare = re.finditer(r'if\s*\(\s*(?:!strcmp|strcmp\s*\(.+==\s*0)\s*\(\s*argv\s*\[\s*[^\]]+\]\s*,\s*["\'](-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)["\']', content)
        for match in arg_compare:
            args.add(match.group(1))
        
        # Pattern 4: Looking for help strings and usage messages
        usage_patterns = re.finditer(r'(?:printf|fprintf)\s*\([^,]*,\s*["\']([^"\']+Usage[^"\']*)["\']', content, re.IGNORECASE)
        for match in usage_patterns:
            usage_text = match.group(1)
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', usage_text)
            for opt_match in opt_matches:
                args.add(opt_match.group(1))
        
        # Pattern 5: Looking for help information in string arrays
        help_arrays = re.finditer(r'(?:static\s+)?(?:const\s+)?(?:char\s*\*|string)\s+\w+\s*\[\s*\]\s*=\s*\{([^}]+)\}', content)
        for match in help_arrays:
            array_content = match.group(1)
            if 'help' in array_content.lower() or 'usage' in array_content.lower():
                opt_matches = re.finditer(r'["\']([^"\']*-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)["\']', array_content)
                for opt_match in opt_matches:
                    text = opt_match.group(1)
                    # Extract just the option part
                    option_matches = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', text)
                    for option in option_matches:
                        args.add(option.group(1))
    
    except Exception as e:
        logger.debug(f"Error extracting args from C/C++ code {filepath}: {e}")
    
    return args

def extract_args_from_go_code(filepath: Path) -> Set[str]:
    """Extract arguments from Go source code."""
    args = set()
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Pattern 1: flag package standard usage
        flag_patterns = [
            r'flag\.(?:String|Int|Bool|Float\d*|Duration)\s*\(\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']',
            r'flag\.(?:String|Int|Bool|Float\d*|Duration)Var\s*\([^,]+,\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']',
        ]
        
        for pattern in flag_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                args.add(f'--{match.group(1)}')
                # Go also automatically adds short forms for single-character flags
                if len(match.group(1)) == 1:
                    args.add(f'-{match.group(1)}')
        
        # Pattern 2: cobra/viper package usage (common in Go CLI apps)
        cobra_patterns = [
            r'cmd\.Flags\(\)\.(?:String|Int|Bool|Float\d*|Duration)\s*\(\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']',
            r'(?:rootCmd|cmd)\.PersistentFlags\(\)\.(?:String|Int|Bool|Float\d*|Duration)\s*\(\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']',
            r'pflags\.(?:String|Int|Bool|Float\d*|Duration)\s*\(\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\']',
        ]
        
        for pattern in cobra_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                args.add(f'--{match.group(1)}')
        
        # Pattern 3: Short and long flags in cobra
        shortlong_patterns = re.finditer(r'Flags\(\)\.(?:String|Int|Bool|Float\d*|Duration)P?\s*\(\s*["\']([a-zA-Z0-9][-a-zA-Z0-9_]*)["\'],\s*["\']([a-zA-Z])["\']', content)
        for match in shortlong_patterns:
            args.add(f'--{match.group(1)}')
            args.add(f'-{match.group(2)}')
        
        # Pattern 4: Help text in usage strings
        usage_patterns = re.finditer(r'(?:Use|Short|Long|Example):\s*["\']([^"\']+)["\']', content)
        for match in usage_patterns:
            usage_text = match.group(1)
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*)', usage_text)
            for opt_match in opt_matches:
                args.add(opt_match.group(1))
    
    except Exception as e:
        logger.debug(f"Error extracting args from Go code {filepath}: {e}")
    
    return args

def extract_args_from_binary_advanced(filepath: Path) -> Set[str]:
    """Advanced extraction of arguments from binary files."""
    args = set()
    
    try:
        # Use strings command to extract strings from the binary
        strings_output = subprocess.check_output(['strings', filepath], text=True)
        
        # Pattern 1: Look for common help text patterns that might indicate options
        help_sections = re.finditer(r'(?:usage|options|arguments|help|flags)(?::|=|-|\s+).{0,800}', 
                                     strings_output, re.IGNORECASE | re.DOTALL)
        
        for section in help_sections:
            section_text = section.group(0)
            
            # Look for option-like patterns in these sections
            # Modified pattern to be more accurate for typical CLI arguments
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z][a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,})?(?:=\w*)?)', section_text)
            for match in opt_matches:
                # Get just the option part, not any value that might be specified
                candidate = match.group(1).split('=')[0]
                
                # Further filter to reduce false positives
                if not re.match(r'-{1,2}[0-9.]+$', candidate) and len(candidate) >= 2:
                    args.add(candidate)
        
        # Pattern 2: Look for standard GNU-style options
        gnu_style = [
            r'--help', r'--version', r'--verbose', r'--quiet', r'--silent',
            r'--config', r'--output', r'--debug', r'--force', r'--all',
            r'-h', r'-v', r'-o', r'-f', r'-a', r'-d', r'-c', r'-s', r'-q'
        ]
        
        for pattern in gnu_style:
            if pattern in strings_output:
                args.add(pattern)
        
        # Pattern 3: Look for option-value pairs in typical formats
        opt_value_pattern = re.finditer(r'(-{1,2}[a-zA-Z][a-zA-Z0-9_-]{1,})(?:[ =][a-zA-Z0-9_-]+)?', strings_output)
        for match in opt_value_pattern:
            candidate = match.group(1)
            # Filter to reduce false positives
            if (not candidate.endswith('-') and 
                not candidate.endswith('--') and
                not candidate.startswith('--__') and
                len(candidate) >= 2):
                args.add(candidate)
        
        # Pattern 4: Look for options in error messages
        error_msgs = re.finditer(r'(?:missing|unknown|invalid|required|expected)\s+(?:option|argument|parameter|flag)(?:[:\s]+)([^,.\n]+)', 
                                 strings_output, re.IGNORECASE)
        
        for match in error_msgs:
            error_text = match.group(1)
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z][a-zA-Z0-9_-]+)', error_text)
            for opt_match in opt_matches:
                args.add(opt_match.group(1))
        
        # Pattern 5: Look for options in format strings
        format_strings = re.finditer(r'%(?:[0-9]+(?:\.[0-9]+)?)?[sdioxXufFeEgGaAcsp]', strings_output)
        nearby_args = 20  # How many characters to look around format specifiers
        
        for match in format_strings:
            start = max(0, match.start() - nearby_args)
            end = min(len(strings_output), match.end() + nearby_args)
            context = strings_output[start:end]
            
            opt_matches = re.finditer(r'(-{1,2}[a-zA-Z][a-zA-Z0-9_-]+)', context)
            for opt_match in opt_matches:
                args.add(opt_match.group(1))
        
        # Add some common arguments that are likely to exist in most programs
        common_args = {
            '-h', '--help', '-v', '--version', '-d', '--debug',
            '-q', '--quiet', '-f', '--force', '-o', '--output',
            '-c', '--config', '-V', '--verbose'
        }
        
        # Only add common args if we found at least one argument already
        # This helps prevent false positives for non-CLI binaries
        if args:
            args.update(common_args)
    
    except Exception as e:
        logger.debug(f"Error extracting args from binary {filepath}: {e}")
    
    return args

def extract_args_from_help_safely(filepath: Path, timeout=2) -> Set[str]:
    """Safely extract arguments from --help output using a properly isolated sandbox."""
    help_args = set()
    
    try:
        # Create a temporary directory for sandboxing
        with tempfile.TemporaryDirectory() as sandbox_dir:
            # Create a sandbox script that will run the command with --help
            sandbox_script = os.path.join(sandbox_dir, "run_help.py")
            
            with open(sandbox_script, 'w') as f:
                f.write("""#!/usr/bin/env python3
import os
import sys
import subprocess
import resource
import signal

def timeout_handler(signum, frame):
    # Handler for timeout signal
    sys.exit(1)

def sandbox_process():
    # Set resource limits (CPU, memory, file descriptors, etc.)
    # Limit CPU time to 1 second
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    
    # Limit virtual memory (50MB)
    resource.setrlimit(resource.RLIMIT_AS, (50 * 1024 * 1024, 50 * 1024 * 1024))
    
    # Limit number of processes to prevent fork bombs
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (5, 5))
    except (ValueError, resource.error):
        pass  # Some systems might not support this
    
    # Limit file size to prevent filling disk (1MB)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    
    # Create a secure environment
    secure_env = {
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
        "DISPLAY": "",  # Disable X11 forwarding
        "NO_AT_BRIDGE": "1",  # Disable AT-SPI D-Bus launching
        "PYTHONIOENCODING": "utf-8",
        "HOME": os.getcwd(),  # Restrict home directory
    }
    
    # Execute the command with --help
    command = sys.argv[1]
    
    # Set a signal handler for timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(1)  # 1 second timeout
    
    try:
        # Use unbuffered operation and redirect stderr to stdout
        output = subprocess.run(
            [command, "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=1,
            text=True,
            env=secure_env,
            # Prevent interactive prompts or GUI access
            stdin=subprocess.DEVNULL
        ).stdout
        print(output)
    except subprocess.TimeoutExpired:
        print("Command timed out")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Clear the alarm
        signal.alarm(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: run_help.py <command>", file=sys.stderr)
        sys.exit(1)
    
    sandbox_process()
""")
            
            # Make the sandbox script executable
            os.chmod(sandbox_script, 0o755)
            
            # Run the sandbox script in a subprocess with timeout
            try:
                # Create a secure environment variables set
                secure_env = os.environ.copy()
                secure_env.update({
                    "DISPLAY": "",  # Disable X11 forwarding
                    "NO_AT_BRIDGE": "1",  # Disable AT-SPI
                    "TERM": "dumb",  # Disable terminal features
                })
                
                proc = subprocess.run(
                    ["python3", sandbox_script, str(filepath)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    text=True,
                    env=secure_env,
                    # Prevent GUI access by not connecting to any TTY
                    stdin=subprocess.DEVNULL
                )
                
                help_output = proc.stdout
                
                # Look for argument patterns in help output
                arg_matches = re.finditer(r'(-{1,2}[a-zA-Z][a-zA-Z0-9_-]+)(?:\s+[A-Z_]+)?(?:\s+|\t|\n)', help_output)
                for match in arg_matches:
                    help_args.add(match.group(1))
                
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout running help command for {filepath}")
            except Exception as e:
                logger.debug(f"Error extracting help output from {filepath} safely: {e}")
    
    except Exception as e:
        logger.debug(f"Error in sandbox setup for {filepath}: {e}")
    
    return help_args


def extract_args_from_executable(filepath: Path, scan_manpages=False, scan_help=False, verbose=False, min_confidence=1) -> Tuple[Set[str], Dict[str, int]]:
    """Process a single executable file and return its extracted arguments and confidence scores."""
    args = set()
    confidence_scores = {}  # Track confidence scores for each arg
    
    if is_executable(filepath):
        try:
            file_type = get_file_type(filepath)
            executable_name = filepath.name
            
            # Check the file type and apply appropriate extraction methods
            extracted_args = set()
            
            # Track extraction methods that found arguments
            extraction_methods_with_args = []
            
            if file_type.startswith('text/'):
                # Handle script files
                shebang = extract_shebang(filepath)
                
                # 1. Check for Python scripts
                if filepath.suffix == '.py' or (shebang and 'python' in shebang.lower()):
                    python_args = extract_args_from_python_script(filepath)
                    if python_args:
                        extracted_args.update(python_args)
                        extraction_methods_with_args.append('python_script')
                
                # 2. Check for shell scripts
                elif filepath.suffix in ('.sh', '.bash') or (shebang and any(sh in shebang.lower() for sh in ['bash', 'sh', 'zsh', 'dash'])):
                    shell_args = extract_args_from_shell_script(filepath)
                    if shell_args:
                        extracted_args.update(shell_args)
                        extraction_methods_with_args.append('shell_script')
                
                # 3. Check for C/C++ source files
                elif filepath.suffix in ('.c', '.h', '.cpp', '.cc', '.hpp', '.cxx'):
                    c_args = extract_args_from_c_cpp_code(filepath)
                    if c_args:
                        extracted_args.update(c_args)
                        extraction_methods_with_args.append('c_cpp_source')
                
                # 4. Check for Go source files
                elif filepath.suffix == '.go':
                    go_args = extract_args_from_go_code(filepath)
                    if go_args:
                        extracted_args.update(go_args)
                        extraction_methods_with_args.append('go_source')
                
                # 5. Generic text file scanning for arguments as a fallback
                else:
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        generic_patterns = [
                            r'(?:\'|")(-{1,2}[a-zA-Z][a-zA-Z0-9_-]+)(?:\'|")',  # Quoted options
                            r'(?:^|\s)(-{1,2}[a-zA-Z][a-zA-Z0-9_-]{2,})(?:\s|$)'  # Space-delimited options (with length filter)
                        ]
                        
                        for pattern in generic_patterns:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                candidate = match.group(1)
                                if len(candidate) > 2 or candidate in ['-h', '-v', '-d', '-f']:  # Accept short common options
                                    extracted_args.add(candidate)
                        
                        if extracted_args:
                            extraction_methods_with_args.append('generic_script')
                    except Exception as e:
                        logger.debug(f"Error in generic extraction for {filepath}: {e}")
            
            # Handle binary files
            elif file_type.startswith('application/'):
                bin_args = extract_args_from_binary_advanced(filepath)
                if bin_args:
                    extracted_args.update(bin_args)
                    extraction_methods_with_args.append('binary_static')
            
            # Try to extract from man pages if enabled
            if scan_manpages:
                man_page = find_man_page(executable_name)
                if man_page:
                    man_args = extract_args_from_man_page(man_page)
                    if man_args:
                        extracted_args.update(man_args)
                        extraction_methods_with_args.append('man_page')
            
            # Try to parse --help output if enabled and if we found few or no arguments
            if scan_help and (not extracted_args or len(extracted_args) < 5):
                help_args = extract_args_from_help_safely(filepath)
                if help_args:
                    extracted_args.update(help_args)
                    extraction_methods_with_args.append('help_output')
                    
            # Alternative approach for running --help directly (with better error handling)
            if scan_help and (not extracted_args or len(extracted_args) < 5):
                try:
                    # Skip direct execution - rely only on the sandboxed approach
                    logger.debug(f"Skipping direct help execution for {filepath} for security reasons")
                    # Instead of direct execution, add common arguments that might be present
                    common_help_args = {'-h', '--help', '-v', '--version', '--verbose', '-q', '--quiet'}
                    extracted_args.update(common_help_args)
                except Exception as e:
                    logger.debug(f"Error extracting help output from {filepath}: {e}")
            
            # Calculate confidence scores based on extraction methods
            for arg in extracted_args:
                # Start with a base confidence of 1
                confidence = 1
                
                # Increase confidence based on which methods found this argument
                if 'python_script' in extraction_methods_with_args:
                    confidence += 2
                if 'shell_script' in extraction_methods_with_args:
                    confidence += 2
                if 'c_cpp_source' in extraction_methods_with_args or 'go_source' in extraction_methods_with_args:
                    confidence += 2
                if 'man_page' in extraction_methods_with_args:
                    confidence += 3
                if 'help_output' in extraction_methods_with_args:
                    confidence += 3
                if 'binary_static' in extraction_methods_with_args:
                    confidence += 1
                
                # Higher confidence for standard argument patterns
                if re.match(r'--[a-z][-a-z0-9]+', arg):  # Standard long option
                    confidence += 1
                if arg in ['-h', '--help', '-v', '--version']:  # Common options
                    confidence += 2
                
                # Lower confidence for suspicious patterns
                if re.match(r'-\d+', arg):  # Likely a negative number
                    confidence -= 2
                if '-' in arg[2:] and '--' in arg:  # Double dash with embedded dash
                    confidence -= 1
                
                confidence_scores[arg] = max(1, min(10, confidence))  # Clamp to 1-10 range
            
            # Filter arguments by confidence threshold
            args = {arg for arg in extracted_args if confidence_scores.get(arg, 0) >= min_confidence}
            
            if verbose:
                if args:
                    logger.info(f"Found {len(args)} arguments for {executable_name} using methods: {', '.join(extraction_methods_with_args)}")
                else:
                    logger.info(f"No arguments found for {executable_name}")
        
        except Exception as e:
            if verbose:
                logger.error(f"Error processing {filepath}: {e}")
    
    return args, confidence_scores


def sanitize_function_name(name):
    """Create a valid bash function name from the executable name."""
    # Replace invalid characters with underscores
    # Only allow alphanumeric and underscore
    valid_chars = set(string.ascii_letters + string.digits + '_')
    sanitized = ''.join(c if c in valid_chars else '_' for c in name)
    
    # Ensure it doesn't start with a digit
    if sanitized and sanitized[0].isdigit():
        sanitized = 'f_' + sanitized
        
    # Ensure it's not empty
    if not sanitized:
        sanitized = 'completion_func'
    
    return sanitized

def generate_bash_completion(executable_name, args, confidence_scores=None):
    """Generate a bash completion script with improved argument handling."""
    if not args:
        return ""
    
    try:
        # Sanitize function name to avoid bash errors
        sanitized_name = sanitize_function_name(executable_name.replace('-', '_').replace('.', '_'))
        
        # Build the options string with the arguments sorted by confidence if available
        if confidence_scores:
            # Get args with confidence scores and sort by confidence (highest first)
            args_with_confidence = [(arg, confidence_scores.get(arg, 1)) for arg in args]
            sorted_args = [arg for arg, _ in sorted(args_with_confidence, key=lambda x: x[1], reverse=True)]
        else:
            sorted_args = sorted(args)
        
        # Sanitize and escape the options
        sanitized_args = []
        for arg in sorted_args:
            # Filter out problematic args
            if any(c in arg for c in '"`$\\'):
                # Skip arguments with bash special characters
                continue
                
            # Only include valid argument patterns
            if re.match(r'^-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*$', arg):
                sanitized_args.append(arg)
        
        # If no valid args remain after filtering, return empty string
        if not sanitized_args:
            return ""
        
        # Generate the options string, properly escaped for bash
        opts = ' '.join(sanitized_args)
        
        # Generate an improved completion script with better handling for different argument types
        completion_script = f"""
# Bash completion for {executable_name}
_complete_{sanitized_name}() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    opts="{{opts}}"

    # Handle special completion for specific arguments
    case "$prev" in
"""
        
        # Add special handling for common arguments that take files or directories
        file_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['file', 'path', 'output', 'input', 'config'])]
        dir_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['dir', 'directory', 'folder', 'path'])]
        
        # Add file completion for arguments that likely take files
        for arg in file_args:
            completion_script += f"""
        {arg})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;"""
        
        # Add directory completion for arguments that likely take directories
        for arg in dir_args:
            completion_script += f"""
        {arg})
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;"""
        
        # Close the case statement and add the default completion
        completion_script += f"""
        *)
            ;;
    esac

    # If current word starts with a dash, suggest options
    if [[ $cur == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
}}
complete -F _complete_{sanitized_name} {executable_name}
"""
        
        return completion_script
    except Exception as e:
        logger.debug(f"Error generating bash completion for {executable_name}: {str(e)}")
        return ""  # Return empty string on error

def extract_existing_completions(output_file):
    """Extract existing completion functions from the output file with better error handling."""
    existing_completions = {}
    
    if not os.path.exists(output_file):
        return existing_completions
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
            
            # Find all completion functions
            completion_funcs = re.finditer(r'# Bash completion for ([^\n]+)\n_complete_([^\(]+)\(\)', content)
            for match in completion_funcs:
                try:
                    executable_name = match.group(1)
                    func_name = match.group(2)
                    
                    # Find the start and end of this function block
                    start_idx = match.start()
                    end_marker = f"complete -F _complete_{func_name} {executable_name}"
                    end_idx = content.find(end_marker, start_idx)
                    
                    if end_idx != -1:
                        end_idx = content.find('\n', end_idx) + 1
                        completion_block = content[start_idx:end_idx]
                        existing_completions[executable_name] = completion_block
                except Exception as e:
                    # Skip problematic entries
                    logger.debug(f"Error processing completion function: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error reading existing completions: {e}")
    
    return existing_completions

def load_cache(cache_file):
    """Load cached argument data from a JSON file."""
    cache = {}
    cache_path = os.path.expanduser(cache_file)
    
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                cache = json.load(f)
                logger.info(f"Loaded cache from {cache_path} with {len(cache)} entries")
        except Exception as e:
            logger.error(f"Error loading cache from {cache_path}: {e}")
    
    return cache

def save_cache(cache, cache_file):
    """Save argument data to a cache file."""
    cache_path = os.path.expanduser(cache_file)
    cache_dir = os.path.dirname(cache_path)
    
    # Create cache directory if it doesn't exist
    try:
        os.makedirs(cache_dir, exist_ok=True)
        
        with open(cache_path, 'w') as f:
            json.dump(cache, f)
            logger.info(f"Saved cache to {cache_path} with {len(cache)} entries")
    except Exception as e:
        logger.error(f"Error saving cache to {cache_path}: {e}")

def fix_completion_script(input_file, output_file=None):
    """Fix syntax errors in an existing completion script with improved error handling."""
    if output_file is None:
        output_file = input_file
    
    # Create a backup
    backup_file = f"{input_file}.bak.{int(time.time())}"
    shutil.copy2(input_file, backup_file)
    logger.info(f"Created backup at {backup_file}")
    
    try:
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Fix 1: Fix function names with special characters
        content = re.sub(r'_complete_([^a-zA-Z0-9_\(\)]+)', 
                         lambda m: f"_complete_{sanitize_function_name(m.group(1))}", 
                         content)
        
        # Fix 2: Ensure 'local' is only used inside functions
        # This is a more complex fix that might require parsing the script
        # For now, we'll just ensure all 'local' declarations are within function blocks
        function_blocks = re.finditer(r'_complete_[a-zA-Z0-9_]+\(\)\s*{(.*?)}', content, re.DOTALL)
        fixed_content = content
        for block in function_blocks:
            block_content = block.group(1)
            # Ensure 'local' is declared properly
            if 'local' in block_content and not re.search(r'local\s+[a-zA-Z0-9_]+', block_content):
                fixed_block = block_content.replace('local', 'local cur prev opts')
                fixed_content = fixed_content.replace(block_content, fixed_block)
        
        # Fix 3: Fix array subscripts
        fixed_content = fixed_content.replace('${COMP_WORDS[COMP_CWORD]}', '"${COMP_WORDS[COMP_CWORD]}"')
        fixed_content = fixed_content.replace('${COMP_WORDS[COMP_CWORD-1]}', '"${COMP_WORDS[COMP_CWORD-1]}"')
        
        # Fix 4: Fix mismatched braces
        # Count opening and closing braces in each function
        function_blocks = re.finditer(r'_complete_[a-zA-Z0-9_]+\(\)\s*{', fixed_content)
        for match in function_blocks:
            start_idx = match.end()
            # Find the corresponding closing brace
            brace_count = 1
            for i in range(start_idx, len(fixed_content)):
                if fixed_content[i] == '{':
                    brace_count += 1
                elif fixed_content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        break
            # If we didn't find a matching closing brace, add one
            if brace_count > 0:
                function_name = re.search(r'_complete_([a-zA-Z0-9_]+)', fixed_content[match.start():match.end()]).group(1)
                fixed_content = fixed_content[:i] + "\n}\ncomplete -F _complete_" + function_name + " " + function_name.replace('_', '-') + "\n" + fixed_content[i:]
        
        # Fix 5: Make sure every completion function has a corresponding complete command
        completion_funcs = re.finditer(r'_complete_([a-zA-Z0-9_]+)\(\)', fixed_content)
        for match in completion_funcs:
            func_name = match.group(1)
            complete_cmd = f"complete -F _complete_{func_name}"
            
            if complete_cmd not in fixed_content:
                # Extract the executable name from comments if available
                comment_match = re.search(r'# Bash completion for ([^\n]+)\n_complete_{0}'.format(func_name), fixed_content)
                if comment_match:
                    executable_name = comment_match.group(1)
                else:
                    # Derive executable name from function name
                    executable_name = func_name.replace('_', '-')
                
                # Add the missing complete command
                complete_line = f"complete -F _complete_{func_name} {executable_name}\n"
                fixed_content += complete_line
        
        # Write the fixed content
        with open(output_file, 'w') as f:
            f.write(fixed_content)
        
        logger.info(f"Fixed completion script written to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error fixing completion script: {e}")
        return False
# Improvements to be added to you_autocomplete_me.py

def extract_subcommands(filepath: Path, command_name: str) -> Set[str]:
    """Extract subcommands for commands like git, apt, pip, etc."""
    subcommands = set()
    
    # Common command patterns to look for
    command_patterns = {
        'git': [r'git\s+([a-z][-a-z0-9]+)', r'git-([a-z][-a-z0-9]+)'],
        'pip': [r'pip\s+([a-z][-a-z0-9]+)'],
        'apt': [r'apt\s+([a-z][-a-z0-9]+)'],
        'apt-get': [r'apt-get\s+([a-z][-a-z0-9]+)'],
        'dnf': [r'dnf\s+([a-z][-a-z0-9]+)'],
        'yum': [r'yum\s+([a-z][-a-z0-9]+)'],
        'pacman': [r'pacman\s+[-a-z]([a-z])'],
        'docker': [r'docker\s+([a-z][-a-z0-9]+)'],
        'kubectl': [r'kubectl\s+([a-z][-a-z0-9]+)'],
        'systemctl': [r'systemctl\s+([a-z][-a-z0-9]+)'],
        'npm': [r'npm\s+([a-z][-a-z0-9]+)'],
    }
    
    # Add predefined subcommands for common tools
    predefined_subcommands = {
        'git': ['add', 'commit', 'push', 'pull', 'clone', 'checkout', 'branch', 'merge', 'rebase', 'status', 'log', 'diff', 'fetch', 'remote', 'reset', 'stash', 'tag', 'show'],
        'pip': ['install', 'uninstall', 'freeze', 'list', 'show', 'download', 'search', 'wheel', 'hash', 'completion', 'config', 'debug'],
        'apt': ['install', 'remove', 'purge', 'update', 'upgrade', 'autoremove', 'list', 'search', 'show', 'clean', 'autoclean'],
        'apt-get': ['install', 'remove', 'purge', 'update', 'upgrade', 'autoremove', 'clean', 'autoclean', 'source', 'build-dep', 'download'],
        'dnf': ['install', 'remove', 'update', 'upgrade', 'autoremove', 'list', 'search', 'info', 'clean', 'check', 'history', 'repolist'],
        'yum': ['install', 'remove', 'update', 'upgrade', 'autoremove', 'list', 'search', 'info', 'clean', 'check', 'history', 'repolist'],
        'pacman': ['install', 'remove', 'update', 'upgrade', 'query', 'search', 'database'],
        'docker': ['build', 'run', 'start', 'stop', 'restart', 'exec', 'ps', 'images', 'pull', 'push', 'rmi', 'rm', 'logs', 'inspect', 'network', 'volume', 'compose'],
        'kubectl': ['get', 'describe', 'create', 'apply', 'delete', 'logs', 'exec', 'port-forward', 'run', 'expose', 'scale', 'rollout', 'set', 'explain', 'edit', 'config'],
        'systemctl': ['start', 'stop', 'restart', 'reload', 'enable', 'disable', 'status', 'is-active', 'is-enabled', 'mask', 'unmask', 'list-units', 'list-dependencies'],
        'npm': ['install', 'uninstall', 'update', 'search', 'list', 'init', 'run', 'test', 'publish', 'config', 'audit', 'ci', 'pack', 'outdated'],
        'sudo': [],  # Special case, sudo doesn't have subcommands but needs special handling
        'dpkg': ['install', 'remove', 'purge', 'status', 'list', 'contents', 'info', 'search', 'configure', 'reconfigure'],
    }
    
    # Special case for sudo which needs different completion
    if command_name == 'sudo':
        return {'*'}  # Special token indicating this needs command completion
    
    # Get predefined subcommands
    if command_name in predefined_subcommands:
        subcommands.update(predefined_subcommands[command_name])
    
    # Try to extract subcommands from help output
    try:
        if command_name in ['git', 'pip', 'apt', 'dnf', 'apt-get', 'yum', 'docker', 'kubectl', 'systemctl', 'npm', 'dpkg', 'pacman']:
            # Run the command with help to extract subcommands
            help_output = subprocess.run(
                [command_name, '--help'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=2,
                text=True
            ).stdout
            
            # Look for patterns that resemble subcommands in the help output
            if command_name in command_patterns:
                for pattern in command_patterns[command_name]:
                    matches = re.finditer(pattern, help_output)
                    for match in matches:
                        subcmd = match.group(1)
                        if subcmd and len(subcmd) > 1 and subcmd not in ['the', 'and', 'for', 'you', 'can', 'use']:
                            subcommands.add(subcmd)
    except Exception:
        pass  # Continue with predefined commands if help extraction fails
    
    # Try extracting from man pages if available
    try:
        man_page = find_man_page(command_name)
        if man_page:
            # Read man page content
            if man_page.endswith('.gz'):
                with gzip.open(man_page, 'rt', errors='ignore') as f:
                    content = f.read()
            else:
                with open(man_page, 'r', errors='ignore') as f:
                    content = f.read()
            
            # Look for COMMANDS or SUBCOMMANDS section
            section_matches = re.finditer(r'\.SH (?:COMMANDS|SUBCOMMANDS)(?:\n|.)*?(?:\n\.SH|\Z)', 
                                         content, re.MULTILINE | re.DOTALL)
            
            for section_match in section_matches:
                section_text = section_match.group(0)
                
                # Extract command names using bold or italic formatting in man pages
                cmd_patterns = [
                    r'\.(?:TP|IP|PP|B|I)\n\.(?:B|I)\s+([a-z][-a-z0-9]+)',
                    r'\\fB([a-z][-a-z0-9]+)\\fR',
                    r'\.B\s+([a-z][-a-z0-9]+)'
                ]
                
                for pattern in cmd_patterns:
                    matches = re.finditer(pattern, section_text)
                    for match in matches:
                        subcmd = match.group(1)
                        if subcmd and len(subcmd) > 1 and subcmd not in ['the', 'and', 'for', 'you', 'can', 'use']:
                            subcommands.add(subcmd)
    except Exception:
        pass
    
    return subcommands

def generate_enhanced_bash_completion(executable_name, args, subcommands=None, confidence_scores=None):
    """Generate a bash completion script with improved argument handling and subcommand support."""
    if not args and not subcommands:
        return ""
    
    try:
        # Sanitize function name to avoid bash errors
        sanitized_name = sanitize_function_name(executable_name.replace('-', '_').replace('.', '_'))
        
        # Build the options string with the arguments sorted by confidence if available
        if confidence_scores:
            # Get args with confidence scores and sort by confidence (highest first)
            args_with_confidence = [(arg, confidence_scores.get(arg, 1)) for arg in args]
            sorted_args = [arg for arg, _ in sorted(args_with_confidence, key=lambda x: x[1], reverse=True)]
        else:
            sorted_args = sorted(args)
        
        # Sanitize and escape the options
        sanitized_args = []
        for arg in sorted_args:
            # Filter out problematic args
            if any(c in arg for c in '"`$\\'):
                # Skip arguments with bash special characters
                continue
                
            # Only include valid argument patterns
            if re.match(r'^-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*$', arg):
                sanitized_args.append(arg)
        
        # Generate the options string, properly escaped for bash
        opts = ' '.join(sanitized_args)
        
        # Special cases for sudo and other commands that need to complete with commands
        if executable_name == 'sudo' or (subcommands and '*' in subcommands):
            # For sudo and similar commands, we need recursive completion handling
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts cmd
    _get_comp_words_by_ref -n : cur prev words cword
    opts="{2}"
    
    # If we're in the first argument, complete with available commands
    if [ $cword -eq 1 ]; then
        COMPREPLY=( $(compgen -c -- "${{cur}}") )
        return 0
    fi
    
    # For commands like sudo, we need to delegate completion to the target command
    # and all its subsequent subcommands
    
    # First, build a new command line without sudo
    local actual_cmd="${{words[1]}}"
    local actual_args=()
    
    # Skip the first word (sudo) and build the new command line
    for ((i=1; i<cword+1; i++)); do
        actual_args+=( "${{words[i]}}" )
    done
    
    # Determine where we are in the command chain
    # This handles complex chains like: sudo apt-get install package
    if [ $cword -gt 1 ]; then
        # Try to use the completion for the full command chain
        
        # First try our custom completions by checking if the command's completion function exists
        local completion_func=""
        
        # Generate all possible completion function names in decreasing specificity
        # For example, for 'sudo apt-get update':
        # - _complete_apt_get_update
        # - _complete_apt_get
        # - _apt_get
        # - _apt

        # Start with the most specific function (all args combined)
        local cmd_chain=""
        for ((i=1; i<cword; i++)); do
            if [ -n "$cmd_chain" ]; then
                cmd_chain="${{cmd_chain}}_${{words[i]}}"
            else
                cmd_chain="${{words[i]}}"
            fi
        done
        
        # Try our custom completion with all parts of the command
        if [ -n "$cmd_chain" ]; then
            completion_func="_complete_$(echo "$cmd_chain" | tr '-' '_')"
            if type $completion_func &>/dev/null; then
                # Adjust command line for this completion
                COMP_CWORD=$((cword-1))
                COMP_LINE="${{COMP_LINE#{0} }}"
                COMP_POINT=$((COMP_POINT-{3}-1))
                $completion_func
                return 0
            fi
        fi
        
        # Next try just the command itself (e.g., apt-get)
        completion_func="_complete_$(echo "$actual_cmd" | tr '-' '_')"
        if type $completion_func &>/dev/null; then
            # Set up the completion environment for the command
            COMP_WORDS=( "${{actual_args[@]}}" )
            COMP_CWORD=$((cword-1))
            COMP_LINE="${{COMP_LINE#{0} }}"
            COMP_POINT=$((COMP_POINT-{3}-1))
            $completion_func
            return 0
        fi
        
        # Try standard bash completions with underscores
        local bash_func="_$(echo "$actual_cmd" | tr '-' '_')"
        if type $bash_func &>/dev/null; then
            # Set up the completion environment for the command
            COMP_WORDS=( "${{actual_args[@]}}" )
            COMP_CWORD=$((cword-1))
            COMP_LINE="${{COMP_LINE#{0} }}"
            COMP_POINT=$((COMP_POINT-{3}-1))
            $bash_func
            return 0
        fi
        
        # Try the completion with dashes
        bash_func="_$actual_cmd"
        if type $bash_func &>/dev/null; then
            # Set up the completion environment for the command
            COMP_WORDS=( "${{actual_args[@]}}" )
            COMP_CWORD=$((cword-1))
            COMP_LINE="${{COMP_LINE#{0} }}"
            COMP_POINT=$((COMP_POINT-{3}-1))
            $bash_func
            return 0
        fi
        
        # Special handling for apt-get, apt, etc.
        if [[ "$actual_cmd" == "apt-get" || "$actual_cmd" == "apt" ]] && [ $cword -eq 2 ]; then
            # apt-get/apt commands
            COMPREPLY=( $(compgen -W "install remove purge update upgrade autoremove list search show clean autoclean" -- "${{cur}}") )
            return 0
        elif [[ "$actual_cmd" == "apt-get" || "$actual_cmd" == "apt" ]] && [ $cword -gt 2 ]; then
            local subcmd="${{words[2]}}"
            if [[ "$subcmd" == "install" || "$subcmd" == "remove" || "$subcmd" == "purge" ]]; then
                if type apt-cache &>/dev/null; then
                    if [[ "$cur" == -* ]]; then
                        # If current word starts with a dash, suggest options
                        COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
                    else
                        # Otherwise suggest package names
                        COMPREPLY=( $(compgen -W "$(apt-cache pkgnames "${{cur}}" 2>/dev/null)" -- "${{cur}}") )
                    fi
                    return 0
                fi
            fi
        elif [[ "$actual_cmd" == "git" ]] && [ $cword -eq 2 ]; then
            # git commands
            COMPREPLY=( $(compgen -W "add commit push pull clone checkout branch merge rebase status log diff fetch remote reset stash tag show" -- "${{cur}}") )
            return 0
        fi
        
        # If we can't find a specific completion, try default completion
        if [[ $cur == -* ]] ; then
            COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
            return 0
        else
            # Default to file completion as a fallback
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
        fi
    fi
}}
complete -F _complete_{1} {0}
""".format(executable_name, sanitized_name, opts, len(executable_name))
            return completion_script
        
        # For commands with subcommands
        if subcommands:
            subcmds_str = ' '.join(sorted(subcommands))
            
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts subcmds
    _get_comp_words_by_ref -n : cur prev words cword
    COMPREPLY=()
    opts="{2}"
    subcmds="{3}"
    
    # Handle special completion for subcommands
    if [[ $cword -eq 1 ]]; then
        # First argument should be a subcommand
        COMPREPLY=( $(compgen -W "${{subcmds}}" -- "${{cur}}") )
        return 0
    fi
    
    # Get the subcommand (second word)
    local subcmd="${{words[1]}}"
    
    # Special handling for specific subcommands
    case "$subcmd" in
""".format(executable_name, sanitized_name, opts, subcmds_str)
            
            # Add special handling for common subcommands based on the executable
            if executable_name == 'git':
                completion_script += """
        checkout|branch|switch)
            # Complete with git branches
            if [[ $cword -eq 2 && $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            elif [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(git branch 2>/dev/null | sed 's/^..//')" -- ${cur}) )
            fi
            return 0
            ;;
        pull|push|fetch)
            # Complete with git remotes
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(git remote 2>/dev/null)" -- ${cur}) )
                return 0
            fi
            ;;
"""
            elif executable_name in ['apt', 'apt-get', 'dnf', 'yum']:
                completion_script += """
        install|remove|purge)
            # For package management, complete with package names
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                if type apt-cache &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(apt-cache pkgnames ${cur} 2>/dev/null)" -- ${cur}) )
                elif type dnf &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(dnf list available 2>/dev/null | tail -n +2 | cut -d' ' -f1 | grep -v '\\.')" -- ${cur}) )
                elif type yum &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(yum list available 2>/dev/null | tail -n +2 | cut -d' ' -f1 | grep -v '\\.')" -- ${cur}) )
                fi
            fi
            return 0
            ;;
        search)
            # Just use normal word completion for search
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            fi
            return 0
            ;;
"""
            elif executable_name == 'pip':
                completion_script += """
        install|uninstall|download|show)
            # For pip commands, try to complete with PyPI packages
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                # This is simplified, as a real implementation would need to query PyPI
                COMPREPLY=( $(compgen -W "$(pip list 2>/dev/null | tail -n +3 | cut -d' ' -f1)" -- ${cur}) )
            fi
            return 0
            ;;
"""
            elif executable_name in ['docker', 'kubectl']:
                completion_script += """
        exec|logs|start|stop|restart)
            # Complete with running containers/pods
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                if [[ "$subcmd" != "exec" || $cword -eq 2 ]]; then
                    if type docker &>/dev/null && [[ "${0}" == "docker" ]]; then
                        COMPREPLY=( $(compgen -W "$(docker ps --format '{{.Names}}' 2>/dev/null)" -- ${cur}) )
                    elif type kubectl &>/dev/null && [[ "${0}" == "kubectl" ]]; then
                        COMPREPLY=( $(compgen -W "$(kubectl get pods -o name 2>/dev/null | cut -d/ -f2)" -- ${cur}) )
                    fi
                fi
            fi
            return 0
            ;;
""".format(executable_name)
            elif executable_name == 'systemctl':
                completion_script += """
        start|stop|restart|reload|enable|disable|status)
            # Complete with system services
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                COMPREPLY=( $(compgen -W "$(systemctl list-units --type=service --all --no-legend 2>/dev/null | cut -d' ' -f1 | sed 's/\\.service$//')" -- ${cur}) )
            fi
            return 0
            ;;
"""
            
            # Close the case statement and add default handling
            completion_script += """
        *)
            ;;
    esac
    
    # Handle special completion for specific arguments
    case "$prev" in
"""
            
            # Add file completion for arguments that likely take files
            file_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['file', 'path', 'output', 'input', 'config', 'f'])]
            dir_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['dir', 'directory', 'folder', 'path', 'd'])]
            
            # Add file completion for arguments that likely take files
            for arg in file_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add directory completion for arguments that likely take directories
            for arg in dir_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Close the second case statement and add the default completion
            completion_script += """
        *)
            ;;
    esac

    # If current word starts with a dash, suggest options
    if [[ $cur == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
}
complete -F _complete_{0} {1}
""".format(sanitized_name, executable_name)
        
        else:
            # Generate the basic completion script as before but with device handling
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts
    _get_comp_words_by_ref -n : cur prev words cword
    COMPREPLY=()
    opts="{2}"

    # Handle special completion for specific arguments
    case "$prev" in
""".format(executable_name, sanitized_name, opts)
            
            # Add file completion for arguments that likely take files
            file_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['file', 'path', 'output', 'input', 'config', 'f'])]
            dir_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['dir', 'directory', 'folder', 'path', 'd'])]
            device_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['device', 'dev', 'disk', 'block', 'partition'])]
            
            # Add file completion for arguments that likely take files
            for arg in file_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add directory completion for arguments that likely take directories
            for arg in dir_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add device completion
            for arg in device_args:
                completion_script += """
        {0})
            # Complete with block devices from /dev
            COMPREPLY=( $(compgen -W "$(ls /dev/sd* /dev/hd* /dev/nvme* /dev/vd* /dev/xvd* 2>/dev/null)" -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Close the case statement and add the default completion
            completion_script += """
        *)
            ;;
    esac

    # If current word starts with a dash, suggest options
    if [[ $cur == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
    
    # For some common applications, add specific handling
    if [[ "{0}" == "mount" || "{0}" == "umount" ]]; then
        # Complete with block devices or mountpoints
        if [[ $cword -eq 1 ]]; then
            COMPREPLY=( $(compgen -W "$(ls /dev/sd* /dev/hd* /dev/nvme* /dev/vd* /dev/xvd* 2>/dev/null)" -- "${{cur}}") )
        else
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
        fi
        return 0
    fi
}}
complete -F _complete_{1} {0}
""".format(executable_name, sanitized_name)
        
        return completion_script
    except Exception as e:
        logger.debug(f"Error generating enhanced bash completion for {executable_name}: {str(e)}")
        return ""  # Return empty string on error
    """Generate a bash completion script with improved argument handling and subcommand support."""
    if not args and not subcommands:
        return ""
    
    try:
        # Sanitize function name to avoid bash errors
        sanitized_name = sanitize_function_name(executable_name.replace('-', '_').replace('.', '_'))
        
        # Build the options string with the arguments sorted by confidence if available
        if confidence_scores:
            # Get args with confidence scores and sort by confidence (highest first)
            args_with_confidence = [(arg, confidence_scores.get(arg, 1)) for arg in args]
            sorted_args = [arg for arg, _ in sorted(args_with_confidence, key=lambda x: x[1], reverse=True)]
        else:
            sorted_args = sorted(args)
        
        # Sanitize and escape the options
        sanitized_args = []
        for arg in sorted_args:
            # Filter out problematic args
            if any(c in arg for c in '"`$\\'):
                # Skip arguments with bash special characters
                continue
                
            # Only include valid argument patterns
            if re.match(r'^-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*$', arg):
                sanitized_args.append(arg)
        
        # Generate the options string, properly escaped for bash
        opts = ' '.join(sanitized_args)
        
        # Special cases for sudo and other commands that need to complete with commands
        if executable_name == 'sudo' or (subcommands and '*' in subcommands):
            # For sudo and similar commands, we need to call another command's completion
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts cmd
    _get_comp_words_by_ref -n : cur prev words cword
    opts="{2}"
    
    # If we're in the first argument, complete with available commands
    if [ $cword -eq 1 ]; then
        COMPREPLY=( $(compgen -c -- "${{cur}}") )
        return 0
    fi
    
    # If the second word is a command, try to use its completion
    if [ $cword -gt 1 ]; then
        cmd="${{words[1]}}"
        # Try to find completion function for the command
        
        # Generate sanitized name for the possible completion function
        cmd_func_name="_complete_$(echo "$cmd" | tr '-' '_')"
        
        # Check for our custom completion function
        if type $cmd_func_name &>/dev/null; then
            # Create new command line args, adjusting for the wrapper
            local cmd_args=( "$cmd" )
            for ((i=2; i<cword+1; i++)); do
                cmd_args+=( "${{words[i]}}" )
            done
            
            # Set up the completion environment for the command
            COMP_WORDS=( "${{cmd_args[@]}}" )
            COMP_CWORD=$((cword-1))
            COMP_LINE="${{COMP_LINE#{0} }}"
            COMP_POINT=$((COMP_POINT-{3}-1))
            
            # Call the command's completion function
            $cmd_func_name
            return 0
            
        # Next try the standard completion function if available
        elif type _$cmd &>/dev/null; then
            # Create new command line args, adjusting for the wrapper
            local cmd_args=( "$cmd" )
            for ((i=2; i<cword+1; i++)); do
                cmd_args+=( "${{words[i]}}" )
            done
            
            # Set up the completion environment for the command
            COMP_WORDS=( "${{cmd_args[@]}}" )
            COMP_CWORD=$((cword-1))
            COMP_LINE="${{COMP_LINE#{0} }}"
            COMP_POINT=$((COMP_POINT-{3}-1))
            
            # Call the standard completion function
            _$cmd
            return 0
            
        # If still not found, try to use default completion
        else
            # Fall back to completing with our own options
            if [[ $cur == -* ]] ; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
                return 0
            else
                # Default to file completion as a fallback
                COMPREPLY=( $(compgen -f -- "${{cur}}") )
                return 0
            fi
        fi
    fi
}}
complete -F _complete_{1} {0}
""".format(executable_name, sanitized_name, opts, len(executable_name))
            return completion_script
        
        # For commands with subcommands
        if subcommands:
            subcmds_str = ' '.join(sorted(subcommands))
            
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts subcmds
    _get_comp_words_by_ref -n : cur prev words cword
    COMPREPLY=()
    opts="{2}"
    subcmds="{3}"
    
    # Handle special completion for subcommands
    if [[ $cword -eq 1 ]]; then
        # First argument should be a subcommand
        COMPREPLY=( $(compgen -W "${{subcmds}}" -- "${{cur}}") )
        return 0
    fi
    
    # Get the subcommand (second word)
    local subcmd="${{words[1]}}"
    
    # Special handling for specific subcommands
    case "$subcmd" in
""".format(executable_name, sanitized_name, opts, subcmds_str)
            
            # Add special handling for common subcommands based on the executable
            if executable_name == 'git':
                completion_script += """
        checkout|branch|switch)
            # Complete with git branches
            if [[ $cword -eq 2 && $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            elif [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(git branch 2>/dev/null | sed 's/^..//')" -- ${cur}) )
            fi
            return 0
            ;;
        pull|push|fetch)
            # Complete with git remotes
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(git remote 2>/dev/null)" -- ${cur}) )
                return 0
            fi
            ;;
"""
            elif executable_name in ['apt', 'apt-get', 'dnf', 'yum']:
                completion_script += """
        install|remove|purge)
            # For package management, complete with package names
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                if type apt-cache &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(apt-cache pkgnames ${cur} 2>/dev/null)" -- ${cur}) )
                elif type dnf &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(dnf list available 2>/dev/null | tail -n +2 | cut -d' ' -f1 | grep -v '\\.')" -- ${cur}) )
                elif type yum &>/dev/null; then
                    COMPREPLY=( $(compgen -W "$(yum list available 2>/dev/null | tail -n +2 | cut -d' ' -f1 | grep -v '\\.')" -- ${cur}) )
                fi
            fi
            return 0
            ;;
        search)
            # Just use normal word completion for search
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            fi
            return 0
            ;;
"""
            elif executable_name == 'pip':
                completion_script += """
        install|uninstall|download|show)
            # For pip commands, try to complete with PyPI packages
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                # This is simplified, as a real implementation would need to query PyPI
                COMPREPLY=( $(compgen -W "$(pip list 2>/dev/null | tail -n +3 | cut -d' ' -f1)" -- ${cur}) )
            fi
            return 0
            ;;
"""
            elif executable_name in ['docker', 'kubectl']:
                completion_script += """
        exec|logs|start|stop|restart)
            # Complete with running containers/pods
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                if [[ "$subcmd" != "exec" || $cword -eq 2 ]]; then
                    if type docker &>/dev/null && [[ "${0}" == "docker" ]]; then
                        COMPREPLY=( $(compgen -W "$(docker ps --format '{{.Names}}' 2>/dev/null)" -- ${cur}) )
                    elif type kubectl &>/dev/null && [[ "${0}" == "kubectl" ]]; then
                        COMPREPLY=( $(compgen -W "$(kubectl get pods -o name 2>/dev/null | cut -d/ -f2)" -- ${cur}) )
                    fi
                fi
            fi
            return 0
            ;;
""".format(executable_name)
            elif executable_name == 'systemctl':
                completion_script += """
        start|stop|restart|reload|enable|disable|status)
            # Complete with system services
            if [[ $cur == -* ]]; then
                COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
            else
                COMPREPLY=( $(compgen -W "$(systemctl list-units --type=service --all --no-legend 2>/dev/null | cut -d' ' -f1 | sed 's/\\.service$//')" -- ${cur}) )
            fi
            return 0
            ;;
"""
            
            # Close the case statement and add default handling
            completion_script += """
        *)
            ;;
    esac
    
    # Handle special completion for specific arguments
    case "$prev" in
"""
            
            # Add file completion for arguments that likely take files
            file_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['file', 'path', 'output', 'input', 'config', 'f'])]
            dir_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['dir', 'directory', 'folder', 'path', 'd'])]
            
            # Add file completion for arguments that likely take files
            for arg in file_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add directory completion for arguments that likely take directories
            for arg in dir_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Close the second case statement and add the default completion
            completion_script += """
        *)
            ;;
    esac

    # If current word starts with a dash, suggest options
    if [[ $cur == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
}
complete -F _complete_{0} {1}
""".format(sanitized_name, executable_name)
        
        else:
            # Generate the basic completion script as before but with device handling
            completion_script = """
# Bash completion for {0}
_complete_{1}() {{
    local cur prev words cword opts
    _get_comp_words_by_ref -n : cur prev words cword
    COMPREPLY=()
    opts="{2}"

    # Handle special completion for specific arguments
    case "$prev" in
""".format(executable_name, sanitized_name, opts)
            
            # Add file completion for arguments that likely take files
            file_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['file', 'path', 'output', 'input', 'config', 'f'])]
            dir_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['dir', 'directory', 'folder', 'path', 'd'])]
            device_args = [arg for arg in sanitized_args if any(hint in arg for hint in ['device', 'dev', 'disk', 'block', 'partition'])]
            
            # Add file completion for arguments that likely take files
            for arg in file_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add directory completion for arguments that likely take directories
            for arg in dir_args:
                completion_script += """
        {0})
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Add device completion
            for arg in device_args:
                completion_script += """
        {0})
            # Complete with block devices from /dev
            COMPREPLY=( $(compgen -W "$(ls /dev/sd* /dev/hd* /dev/nvme* /dev/vd* /dev/xvd* 2>/dev/null)" -- "${{cur}}") )
            return 0
            ;;""".format(arg)
            
            # Close the case statement and add the default completion
            completion_script += """
        *)
            ;;
    esac

    # If current word starts with a dash, suggest options
    if [[ $cur == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi
    
    # For some common applications, add specific handling
    if [[ "{0}" == "mount" || "{0}" == "umount" ]]; then
        # Complete with block devices or mountpoints
        if [[ $cword -eq 1 ]]; then
            COMPREPLY=( $(compgen -W "$(ls /dev/sd* /dev/hd* /dev/nvme* /dev/vd* /dev/xvd* 2>/dev/null)" -- "${{cur}}") )
        else
            COMPREPLY=( $(compgen -d -- "${{cur}}") )
        fi
        return 0
    fi
}}
complete -F _complete_{1} {0}
""".format(executable_name, sanitized_name)
        
        return completion_script
    except Exception as e:
        logger.debug(f"Error generating enhanced bash completion for {executable_name}: {str(e)}")

# Update the main function to use the new enhanced completion generator
def process_executable(filepath: Path, args):
    """Process a single executable file and return its extracted arguments, subcommands, and confidence scores."""
    extracted_args, confidence_scores = extract_args_from_executable(
        filepath, args.scan_manpages, args.scan_help, args.verbose, args.min_confidence
    )

    # Check if this is a command that might have subcommands
    executable_name = filepath.name
    subcommands = set()
    
    # Check if this command might have subcommands based on name
    if executable_name in ['git', 'pip', 'apt', 'apt-get', 'dnf', 'yum', 'pacman', 'docker', 
                           'kubectl', 'systemctl', 'npm', 'sudo', 'dpkg']:
        subcommands = extract_subcommands(filepath, executable_name)
    
    return extracted_args, subcommands, confidence_scores

def main():
    start_time = time.time()
    args = parse_arguments()
    
    # Setup logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    
    # If fix-only mode is requested, fix the script and exit
    if args.fix:
        output_file = args.output
        if not output_file:
            output_file = os.path.expanduser("~/.bash_completion.d/auto_completions.sh")
        
        if os.path.exists(output_file):
            logger.info(f"Attempting to fix completion script: {output_file}")
            success = fix_completion_script(output_file)
            if success:
                print("Completion script fixed successfully. Try sourcing it again:")
                print(f"source {output_file}")
            else:
                print("Failed to fix completion script.")
            sys.exit(0 if success else 1)
        else:
            print(f"Completion script not found at {output_file}")
            sys.exit(1)
    
    # Load cache if enabled
    cache = {}
    if args.cache:
        cache = load_cache(args.cache_file)
    
    # Determine directories to scan
    directories_to_scan = []
    
    # Process PATH if requested
    if args.scan_path or (args.directories and '$PATH' in args.directories):
        path_dirs = os.environ.get('PATH', '').split(':')
        directories_to_scan.extend([Path(d) for d in path_dirs if d])
        # Remove $PATH from the list if it was explicitly specified
        if args.directories and '$PATH' in args.directories:
            args.directories.remove('$PATH')
    
    # Add explicitly specified directories
    if args.directories:
        directories_to_scan.extend([Path(os.path.expanduser(d)) for d in args.directories])
    elif not args.scan_path:
        # If no directories specified and not scanning PATH, use current directory
        directories_to_scan.append(Path('.'))
    
    # Remove duplicates while preserving order
    seen = set()
    directories_to_scan = [d for d in directories_to_scan if not (d in seen or seen.add(d))]
    
    # Determine output file
    if args.output:
        output_file = os.path.expanduser(args.output)
    else:
        # Create ~/.bash_completion.d directory if it doesn't exist
        completion_dir = os.path.expanduser("~/.bash_completion.d")
        os.makedirs(completion_dir, exist_ok=True)
        output_file = os.path.join(completion_dir, "auto_completions.sh")
    
    # Extract existing completions if not using --new
    existing_completions = {}
    if not args.new and os.path.exists(output_file):
        existing_completions = extract_existing_completions(output_file)
        if args.verbose:
            logger.info(f"Found {len(existing_completions)} existing completion functions")
    
    # Collect all executable files from the specified directories
    executable_files = []
    for directory in directories_to_scan:
        if not directory.exists() or not directory.is_dir():
            logger.warning(f"Directory '{directory}' does not exist or is not a directory. Skipping.")
            continue
        
        if args.verbose:
            logger.info(f"Scanning directory: {directory}")
        
        for filepath in directory.iterdir():
            if filepath.is_file() and is_executable(filepath):
                executable_files.append(filepath)
    
    logger.info(f"Found {len(executable_files)} executable files to analyze")
    
    # Process executables in parallel
    new_completions = {}
    executable_args = {}
    executable_subcommands = {}  # New dictionary to store subcommands
    execution_errors = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        # Create a dictionary to store futures and their corresponding filepaths
        future_to_filepath = {}
        
        # Process each file
        for filepath in executable_files:
            # Check if we have this in the cache and its mtime hasn't changed
            cache_key = str(filepath)
            file_mtime = os.path.getmtime(filepath)
            
            # Use cached results if available and valid
            if args.cache and cache_key in cache and cache[cache_key].get('mtime') == file_mtime:
                cached_args = set(cache[cache_key]['args'])
                cached_conf = cache[cache_key]['confidence']
                cached_subcommands = set(cache[cache_key].get('subcommands', []))  # Get cached subcommands
                
                if cached_args or cached_subcommands:  # Use either args or subcommands
                    executable_name = filepath.name
                    executable_args[executable_name] = cached_args
                    executable_subcommands[executable_name] = cached_subcommands
                    
                    # Generate enhanced completion script
                    try:
                        completion = generate_enhanced_bash_completion(
                            executable_name, cached_args, cached_subcommands, cached_conf
                        )
                        if completion:  # Only add if non-empty
                            new_completions[executable_name] = completion
                            
                        if args.verbose:
                            logger.info(f"Using cached data for {executable_name}: {len(cached_args)} arguments, {len(cached_subcommands)} subcommands")
                    except Exception as e:
                        execution_errors += 1
                        logger.error(f"Error generating completion for {executable_name}: {e}")
            else:
                # Submit for processing using the new process_executable function
                future_to_filepath[executor.submit(process_executable, filepath, args)] = filepath
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_filepath):
            filepath = future_to_filepath[future]
            try:
                extracted_args, extracted_subcommands, confidence_scores = future.result()
                
                if extracted_args or extracted_subcommands:
                    executable_name = filepath.name
                    executable_args[executable_name] = extracted_args
                    executable_subcommands[executable_name] = extracted_subcommands
                    
                    # Generate enhanced completion script
                    try:
                        completion = generate_enhanced_bash_completion(
                            executable_name, extracted_args, extracted_subcommands, confidence_scores
                        )
                        if completion:  # Only add if non-empty
                            new_completions[executable_name] = completion
                            
                            # Update cache
                            if args.cache:
                                cache_key = str(filepath)
                                cache[cache_key] = {
                                    'mtime': os.path.getmtime(filepath),
                                    'args': list(extracted_args),
                                    'subcommands': list(extracted_subcommands),
                                    'confidence': confidence_scores
                                }
                    except Exception as e:
                        execution_errors += 1
                        logger.error(f"Error generating completion for {executable_name}: {e}")
            except Exception as e:
                logger.error(f"Error processing {filepath}: {e}")
                execution_errors += 1
    
    # Save the updated cache
    if args.cache:
        save_cache(cache, args.cache_file)
    
    # Merge with existing completions
    final_completions = existing_completions.copy() if not args.new else {}
    final_completions.update(new_completions)
    
    # Create a backup of the existing file before writing
    if os.path.exists(output_file):
        backup_file = f"{output_file}.bak.{int(time.time())}"
        shutil.copy2(output_file, backup_file)
        if args.verbose:
            logger.info(f"Backup created at {backup_file}")
    
    # Combine all completion scripts
    combined_script = """#!/bin/bash
# Auto-generated bash completion script
# Generated by you_autocomplete_me.py on {date}
# To enable these completions, add the following to your .bashrc:
# if [ -f {output_file} ]; then
#     . {output_file}
# fi

""".format(date=time.strftime("%Y-%m-%d %H:%M:%S"), 
           output_file=output_file)
    
    combined_script += "\n".join(final_completions.values())
    
    # Write to output file
    try:
        with open(output_file, 'w') as f:
            f.write(combined_script)
        print(f"Completion scripts written to {output_file}")
        print(f"Found completions for {len(new_completions)} executables")
        
        # Print statistics on arguments and subcommands found
        total_args = sum(len(args_set) for args_set in executable_args.values())
        total_subcommands = sum(len(subcmds) for subcmds in executable_subcommands.values())
        print(f"Total arguments found: {total_args}")
        print(f"Total subcommands found: {total_subcommands}")
        
        if execution_errors > 0:
            print(f"Encountered {execution_errors} errors during processing, but continued anyway.")
        
        if not args.new and existing_completions:
            preserved = len(existing_completions) - len(set(existing_completions) & set(new_completions))
            print(f"Preserved {preserved} existing completion functions")
        
        # Add helper message to suggest .bashrc modification
        if not os.path.exists(os.path.expanduser("~/.bashrc")) or not output_file:
            print("\nTo enable these completions, add the following to your .bashrc:")
            print(f"if [ -f {output_file} ]; then")
            print(f"    . {output_file}")
            print("fi")
    except Exception as e:
        logger.error(f"Error writing to {output_file}: {e}")
        sys.exit(1)
    
    elapsed_time = time.time() - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()