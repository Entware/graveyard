#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=fkmines
PKG_VERSION:=0.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/fkmines
PKG_MD5SUM:=e5c869b3022dd0fb7cbe7789e3ee617c

include $(INCLUDE_DIR)/package.mk

define Package/fkmines
	SECTION:=games
	CATEGORY:=Games
	DEPENDS:=+libncurses
	TITLE:=a minesweeper clone
	URL:=http://sourceforge.net/projects/fkmines/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/fkmines/description
 A minesweeper clone for linux terminals using ncurses.
endef

define Package/fkmines/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mines $(1)/opt/bin/fkmines
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/generator $(1)/opt/bin/fkgenerator
endef

$(eval $(call BuildPackage,fkmines))
