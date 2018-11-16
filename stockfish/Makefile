#
# Copyright (C) 2011-2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It's working! Tested with https://github.com/antiproton/Web-GUI-for-stockfish-chess

include $(TOPDIR)/rules.mk

PKG_NAME:=stockfish
PKG_VERSION:=9-20181112
PKG_REV:=3cbb05b1b814ef9c79cc97de3598ba0c24735a97
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/official-stockfish/Stockfish.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/stockfish
	SECTION:=games
	CATEGORY:=Games
	TITLE:=UCI chess engine
	DEPENDS:=+libatomic +libstdcpp
	URL:=http://www.stockfishchess.com
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/stockfish/description
 Stockfish is a free UCI chess engine derived from Glaurung 2.1. It is
 not a complete chess program and requires some UCI-compatible GUI.
endef

MAKE_PATH := src
MAKE_FLAGS += build ARCH=general-32
TARGET_LDFLAGS += -latomic

define Package/stockfish/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/stockfish $(1)/opt/bin
endef

$(eval $(call BuildPackage,stockfish))
