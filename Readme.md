[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/emMZvU8G)
# SdE2 Devoir 3 Starter - Rusty Loader

## Solution

TODO Décrivez ici comment avez-vous résolu les devoirs. 

The Executable Analyzer is a Rust program designed to analyze executable files and handle segmentation faults during execution.

1. Segment Analysis: Reads the executable file, parses it to extract information about its segments, and aligns segment addresses and offsets to page boundaries.
2. Entry Point and Base Address Determination: Determines the entry point of the executable and calculates its base address.
3. Signal Handler Registration: Registers a signal handler for segmentation faults.
4. Memory Mapping: When a segmentation fault occurs during execution, the signal handler maps memory pages to handle the fault.
5. Execution: Finally, the program executes the executable, passing the calculated base address and entry point.
