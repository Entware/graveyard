#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-fasteners
PKG_VERSION:=0.16
PKG_RELEASE:=1

PYPI_NAME:=fasteners
PKG_HASH:=c995d8c26b017c5d6a6de9ad29a0f9cdd57de61ae1113d28fac26622b06a0933

include $(TOPDIR)/feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/python3-fasteners
	SECTION:=lang
	CATEGORY:=Languages
	SUBMENU:=Python
	TITLE:=python-fasteners
	URL:=https://github.com/harlowja/fasteners
	MAINTAINER:=Entware team, https://entware.net
	DEPENDS:=+python3-light
endef

define Package/python3-fasteners/description
 Cross platform locks for threads and processes.
endef

$(eval $(call Py3Package,python3-fasteners))
$(eval $(call BuildPackage,python3-fasteners))
