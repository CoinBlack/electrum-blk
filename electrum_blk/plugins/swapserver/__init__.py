from electrum_blk.i18n import _

fullname = _('SwapServer')
description = """
Submarine swap server for an Electrum daemon.

Example setup:

  electrum-blk -o setconfig use_swapserver True
  electrum-blk -o setconfig swapserver_address localhost:5455
  electrum-blk daemon -v

"""

available_for = ['cmdline']
