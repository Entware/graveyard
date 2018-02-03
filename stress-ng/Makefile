#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Пакет рабочий, если нужен, можно перенести в RTNDEV

include $(TOPDIR)/rules.mk

PKG_NAME:=stress-ng
PKG_VERSION:=0.09.14
PKG_REV:=583841275c2bb186af4d28d20497d1ef3885cc06
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/ColinIanKing/stress-ng
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/stress-ng
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=stress tests
	URL:=http://kernel.ubuntu.com/~cking/stress-ng/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/stress-ng/description
 stress-ng will stress test a computer system in various selectable ways.
 It was designed to exercise various physical subsystems of a computer
 as well as the various operating system kernel interfaces.
endef

define Package/stress-ng/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/stress-ng $(1)/opt/bin
endef

$(eval $(call BuildPackage,stress-ng))
