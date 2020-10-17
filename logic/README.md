# Structure of the gigahorse decompiler

`local.dl`: Analyses performed on a per-basic block level

`decompiler.dl`: Entry point for decompiler

`functions.dl`: Function reconstruction logic

`decompiler_output.dl`: Three-address code output logic

`decompiler_analytics.dl`: Logic for computing analytics 

`context-sensitivity/*.dl`: Various kinds of context sensitivities that can be plugged into the decompiler, the default being the transactional context.
