# Fuzzing Test

Your goal is to familiarise yourself with basic fuzzing. The correct flag will cause the program to print "Success". 

You will need to install and learn to use Libfuzzer (https://llvm.org/docs/LibFuzzer.html) that is distributed with clang. Change the main function into a fuzzing harness. You will also have to modify the program in other ways so that fuzzing is successful.

## Hints

What is the probability that the fuzzer passes through the first if that compares the full checksum? Is it needed at all?

