#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# Something wrong with yaml-cpp
#
#src/ap_maps.cpp:14:21: error: 'Load' is not a member of 'YAML'
#   YAML::Node node = YAML::Load(instream);
#                     ^
#src/ap_maps.cpp:16:33: error: 'const class YAML::Node' has no member named 'as'
#   p.protocol = node["protocol"].as<int>();
#

include $(TOPDIR)/rules.mk

PKG_NAME:=asciiportal
PKG_VERSION:=1.3-beta7
PKG_REV:=8cbb2958ba372c8264ac0206d51fd492b41fb7e8
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/cymonsgames/ASCIIpOrtal.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_BUILD_DEPENDS:=yaml-cpp

include $(INCLUDE_DIR)/package.mk

define Package/asciiportal
	SECTION:=games
	CATEGORY:=Games
	DEPENDS:=+libncursesw +libstdcpp
	TITLE:=ASCIIpOrtal game
	URL:=http://cymonsgames.com/asciiportal/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/asciiportal/description
	ASCIIpOrtal is a unique puzzle game. You can create custom maps 
	so even when the game is over the fun doesn’t need to end.
endef

define Package/asciiportal/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/asciiportal $(1)/opt/bin
endef

$(eval $(call BuildPackage,asciiportal))
