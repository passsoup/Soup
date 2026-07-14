"""Export packs — importing this package registers every pack.

Each regulator/buyer document is a small renderer over the same passport. Adding
a regulation means adding a module here and registering it — never a new product.
"""

from __future__ import annotations

# Importing each module runs its register(...) call. More packs (bank-mrm, gdpr,
# eu-ai-act-highrisk, hipaa, nist-ai-rmf) are registered as they are added.
from soup_cli.passport.packs import (  # noqa: F401
    bank_mrm,
    eu_ai_act_gpai,
    model_card,
)
from soup_cli.passport.packs.base import (  # noqa: F401
    Pack,
    all_packs,
    get_pack,
    register,
    render_pack,
)
