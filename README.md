# straceish

Turns stack trace data into human-readable context  
Disclaimer: *This tool was made by ClaudeAI*  

# Usage

command: `strace -f -tt -T -o trace.txt <command> <args>`  

Then we pass the raw trace data `trace.txt`:  

command: `python straceish.py -v trace.txt`  


# Output

<img width="914" height="654" alt="summary" src="https://github.com/user-attachments/assets/2538d06b-f7fd-480b-bf58-27bc33012370" />


*(shows `strace` of `echo 'hello'`)*  
