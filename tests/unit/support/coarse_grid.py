from evals.cve.holdout_hierarchical import Grid

# For tests whose assertions do not depend on the precision of the hierarchical intervals.
COARSE_GRID = Grid(theta_points=40, d_points=16)
