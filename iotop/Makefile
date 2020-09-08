#
# Copyright (C) 2011-2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# Release isn't python3 ready, trunk suffers from

#~ # iotop
#Traceback (most recent call last):
#  File "/opt/sbin/iotop", line 10, in <module>
#    from iotop.ui import main
#  File "/opt/lib/python3.8/site-packages/iotop/ui.py", line 46, in <module>
#    from iotop.data import find_uids, TaskStatsNetlink, ProcessList, Stats
#  File "/opt/lib/python3.8/site-packages/iotop/data.py", line 51, in <module>
#    vmstat_f = VmStat()
#  File "/opt/lib/python3.8/site-packages/iotop/vmstat.py", line 23, in __init__
#    self.vmstat = self.read()
#  File "/opt/lib/python3.8/site-packages/iotop/vmstat.py", line 40, in read
#    return pgpgin, pgpgout
#UnboundLocalError: local variable 'pgpgin' referenced before assignment

include $(TOPDIR)/rules.mk

PKG_NAME:=iotop
PKG_VERSION:=0.6-20200108
PKG_REV:=1bfb3bc70febb1ffb95146b6dcd65257228099a3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://repo.or.cz/iotop.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+python3 +python3-ncurses
	TITLE:=watches I/O usage information output by the Linux kernel
	URL:=http://guichaz.free.fr/iotop/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/$(PKG_NAME)/description
 Iotop is a Python program with a top like UI used to show of behalf of which
 process is the I/O going on.
endef

# XXX error: option --single-version-externally-managed not recognized
PYTHON3_PKG_SETUP_ARGS:=

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/opt
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/opt/{lib,sbin} \
	    $(1)$(PYTHON_PKG_DIR)/opt
	$(call Python3/FixShebang,$(1)/opt/sbin/iotop)
endef

$(eval $(call Py3Package,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)))
