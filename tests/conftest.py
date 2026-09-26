import os
import tempfile

from core.paths import RESULTS_DIR_ENV

# Runs triggered by tests write their stores/evidence/reports to a throwaway
# dir instead of the user's results/BugBounty-Results (core/paths.py). Set at
# import so every default path resolved during collection sees it too.
os.environ.setdefault(RESULTS_DIR_ENV, tempfile.mkdtemp(prefix="bugbounty-test-results-"))
