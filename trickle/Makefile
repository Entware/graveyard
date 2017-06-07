#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Raises an error: Could not find overload object

include $(TOPDIR)/rules.mk

PKG_NAME:=trickle
PKG_VERSION:=1.07-20150113
PKG_REV:=66551ad94ad3d8af83e1e4422804676ac8762f47
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/mariusae/trickle.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/trickle
	SECTION:=net
	CATEGORY:=Network
	TITLE:=userland bandwidth shaper
	DEPENDS:=+libevent2
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/trickle/description
 Trickle is a userland bandwidth shaper for Unix-like systems.
endef

CONFIGURE_ARGS += \
	--with-libevent="$(STAGING_DIR)/opt"

define Package/trickle/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/trickle{,ctl,d} $(1)/opt/bin
endef

$(eval $(call BuildPackage,trickle))
