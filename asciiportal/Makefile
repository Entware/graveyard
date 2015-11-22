
include $(TOPDIR)/rules.mk

PKG_NAME:=asciiportal
PKG_VERSION:=1.3-beta7
PKG_REV:=bbbd50612ec3ffbe8919901c82b4a4a3a0d61c7f
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/cymonsgames/ASCIIpOrtal.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

#PKG_UNPACK=unzip -d $(PKG_BUILD_DIR) $(DL_DIR)/$(PKG_SOURCE)

define Package/asciiportal
	SECTION:=games
	CATEGORY:=Games
	DEPENDS:=+libncursesw +libstdcpp
	TITLE:=ASCIIpOrtal game
	URL:=http://cymonsgames.com/asciiportal/
endef

define Package/asciiportal/description
	ASCIIpOrtal is a unique puzzle game. You can create custom maps 
	so even when the game is over the fun doesn’t need to end.
endef

#define Build/Configure
#	cp  $(PKG_BUILD_DIR)/ASCIIpOrtal-linux-Makefile.txt $(PKG_BUILD_DIR)/Makefile
#	cd $(PKG_BUILD_DIR); \
#	for srcfile in `ls -1 *.cpp *.h`; do \
#	    cat $$$$srcfile | tr -d "\r" > .tmp; \
#	    mv -f .tmp $$$$srcfile; \
#	done;
#endef

define Package/asciiportal/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/asciiportal $(1)/opt/bin
endef

$(eval $(call BuildPackage,asciiportal))
