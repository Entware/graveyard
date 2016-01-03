#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cataclysm
PKG_VERSION:=20120825
PKG_REV:=cf18cea2fd9d49f528b79a54b74ffbfae1ed9465
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/Whales/Cataclysm.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/cataclysm
	SECTION:=games
	CATEGORY:=Games
	DEPENDS:=+libncurses +libstdcpp
	TITLE:=a single-player, post-apocalyptic roguelike
	URL:=https://github.com/Whales/Cataclysm
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/cataclysm/description
 Cataclysm is a post-apocalyptic roguelike, set in the countryside of
 New England after a devastating plague of monsters and zombies.
endef

TARGET_LDFLAGS += \
	-lncurses

define Package/cataclysm/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cataclysm $(1)/opt/bin
endef

$(eval $(call BuildPackage,cataclysm))
