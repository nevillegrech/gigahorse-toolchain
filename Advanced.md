# Tuning Gigahorse

The gigahorse framework offers various ways to tune its underlying algorithms.

## Tuning Context Sensitivity

Gigahorse features different context sensitivity algorithms:
* `TransactionalContext`: The default context sensitivity of Gigahorse. Composite, including a public entry point component and a variable depth selective context component approximating private function calls and returns.
* `CallSiteContext`: Call(or block)-site context sensitivity with a variable depth.
* `CallSiteContextPlus`: The above call-site context including a public function component.
* `SelectiveContext`: Selective call-site context only including with dynamic jumps.
* `SelectiveContextPlus`: The above selective context including a public function component.

You can run the decompilation pipeline with a different context sensitivity algorithm using the -M flag.
Changing the context-sensitivity algorithm using the default 2-step pipeline is not suggested as it will override the default for both configurations.
As an example, the command below will run the example contract using call-site context sensitivity:
```
python3.8 gigahorse.py examples/long_running.hex --single_decomp -M "CONTEXT_SENSITIVITY=CallSiteContext"
```

In addition the `-cd` flag can be used to provide a different maximum context depth.

## Other decompiler options

### Early cloning of blocks

You can use the experimental `--early_cloning` flag to enable the cloning of blocks that are likely to introduce imprecision to the decompilation output. Can end up producing a more precise decompilation output, but on average makes decompilation take 2x as much time.

### Enabling limitsize of certain relations

You can use the `--enable_limitsize` flag to enable souffle's [limitsize](https://souffle-lang.github.io/directives#limit-size-directive) directive abruptly stoping the execution of certain key/heavy relations.
__WARNING:__ Using limitsize will also stop the execution of other relations in the same stratum, can affect the decompilation output in unexpected ways.


### Disabling inlining of small functions

By default, the gigahorse pipeline contains a stage inlining small functions, in order to produce a more high-level IR for subsequent client analyses.
The inlining stage can be disabled using the `--disable_inline` flag.

# Development and Debugging

## Development using `gigahorse.py`

You can use the `--debug` (shows `souffle` warnings/errors, outputs datalog relations using the `DEBUG_OUTPUT()` macro) and `-i` (runs `souffle` in interpreted mode) flags when developing gigahorse or client analyses.

## Running Gigahorse Manually (for development purposes)
To use this framework for development purposes (e.g., writing security analyses), an understanding of the analysis pipeline will be helpful. This section describes one common use case --- that of visualizing the CFG of the lifted IR. The pipeline will consist of the manual execution of following three steps:

1. Fact generation
2. Run main.dl using Souffle
3. Visualize results

In order to proceed, make sure that `LD_LIBRARY_PATH` and `LIBRARY_PATH` are set:

    $ cd souffle-addon
    $ export LD_LIBRARY_PATH=`pwd`  # or wherever you want to put the resulting libfunctors.so
    $ export LIBRARY_PATH=`pwd`  # or wherever you want to put the resulting libfunctors.so

We suggest adding `LD_LIBRARY_PATH` and `LIBRARY_PATH` to your `.bashrc` file


Now let's manually execute the pipeline above:


    $ ./generatefacts <contract> facts      # fact generation (translates EVM bytecode into relational format)
    $ souffle -F facts logic/main.dl  # runs the main decompilation step (written as a Datalog program)
    $ clients/visualizeout.py               # visualizes the IR and outputs (all outputs of Datalog programs are in a relational format)
