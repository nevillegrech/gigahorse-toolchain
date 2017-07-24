"""dataflowsettings.py: a structure for manipulating dataflow analysis settings."""

class DataFlowSettings:
    def __init__(self, max_iterations:int=-1, bailout_seconds:int=-1,
                 remove_unreachable:bool=False, die_on_empty_pop:bool=False,
                 skip_stack_on_overflow:bool=True, reinit_stacks:bool=True,
                 hook_up_stack_vars:bool=True, hook_up_jumps:bool=True,
                 mutate_jumps:bool=False, generate_throws:bool=False,
                 final_mutate_jumps:bool=False, final_generate_throws:bool=True,
                 mutate_blockwise:bool=True, clamp_large_stacks:bool=True,
                 clamp_stack_minimum:int=20, widen_variables:bool=True,
                 widen_threshold:int=20, set_valued_ops:bool=False):
      """
      A plain old data struct for holding various settings related to
      data flow analysis.

      Args:
        max_iterations: the maximum number of times to perform the graph
                        analysis step. A negative value means no maximum.
        bailout_seconds: break out of the analysis loop if the time spent
                         exceeds this value. Not a hard cap as subsequent
                         analysis steps are required, and at least one
                         iteration will always be performed. A negative value
                         means no maximum.
        remove_unreachable: upon completion of the analysis, if there are
                            blocks unreachable from the contract root, remove
                            them.
        die_on_empty_pop: raise an exception if an empty stack is popped.
        skip_stack_on_overflow: do not apply changes to exit stacks after a
                                symbolic overflow occurrs in their blocks.
        reinit_stacks: reinitialise all blocks' exit stacks to be empty.
        hook_up_stack_vars: after completing the analysis, propagate entry
                            stack values into blocks.
        hook_up_jumps: Connect any new edges that can be inferred after
                       performing the analysis.
        mutate_jumps: JUMPIs with known conditions become JUMPs (or are deleted)
        generate_throws: JUMP and JUMPI instructions with invalid destinations
                         become THROW and THROWIs
        final_mutate_jumps: mutate jumps in the final analysis phase
        final_generate_throws: generate throws in the final analysis phase
        mutate_blockwise: hook up stack vars and/or hook up jumps after each
                          block rather than after the whole analysis is
                          complete.
        clamp_large_stacks: if stacks start growing without bound, reduce the
                            maximum stack size in order to hasten convergence.
        clamp_stack_minimum: stack sizes will not be clamped smaller than
                             this value.
        widen_variables: if any stack variable's number of possible values
                         exceeds a given threshold, widen its value to Top.
        widen_threshold: widen if the size of a given variable exceeds this
                         value.
        set_valued_ops: if true, apply arithmetic operations to variables
                        with multiple values; otherwise, only apply them
                        to variables whose value is definite.

      If we have already reached complete information about our stack CFG
      structure and stack states, we can use die_on_empty_pop and reinit_stacks
      to discover places where empty stack exceptions will be thrown.
      """

      self.max_iterations = max_iterations
      self.bailout_seconds = bailout_seconds
      self.remove_unreachable = remove_unreachable
      self.die_on_empty_pop = die_on_empty_pop
      self.skip_stack_on_overflow = skip_stack_on_overflow
      self.reinit_stacks = reinit_stacks
      self.hook_up_stack_vars = hook_up_stack_vars
      self.hook_up_jumps = hook_up_jumps
      self.mutate_jumps = mutate_jumps
      self.generate_throws = generate_throws
      self.mutate_blockwise = mutate_blockwise
      self.clamp_large_stacks = clamp_large_stacks
      self.clamp_stack_minimum = clamp_stack_minimum
      self.widen_variables = widen_variables
      self.widen_threshold = widen_threshold
      self.final_mutate_jumps = final_mutate_jumps
      self.final_generate_throws = final_generate_throws
      self.set_valued_ops = set_valued_ops

