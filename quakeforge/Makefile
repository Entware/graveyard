#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It works, but too heavy for MIPS devices

include $(TOPDIR)/rules.mk

PKG_NAME:=quakeforge
PKG_VERSION:=0.6.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@SF/quake/quake/$(PKG_VERSION)
PKG_MD5SUM:=11c771eee086138fa76c468380743bdd

PKG_INSTALL:=1
PKG_FIXUP:=libtool

include $(INCLUDE_DIR)/package.mk

define Package/quakeforge
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+zlib +libncurses
	TITLE:=A QuakeWorld game engine
	URL:=http://www.quakeforge.net
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/quakeforge/description
	QuakeForge is a source port of Quake and QuakeWorld. The primary development goal is to remain
	compatible with the original games released by id Software while adding
	portability and optional extensions to enhance gameplay.
endef

CONFIGURE_ARGS += \
	--disable-static \
	--enable-static \
	--disable-asmopt \
	--disable-flac \
	--disable-libFLACtest \
	--disable-wildmidi \
	--disable-vorbis \
	--disable-oggtest \
	--disable-vorbistest \
	--disable-png \
	--disable-vidmode \
	--disable-dga \
	--disable-sdl \
	--disable-sdltest \
	--disable-sdl-audio \
	--disable-sdl-cd \
	--disable-alsa \
	--disable-oss \
	--disable-sun \
	--disable-sound \
	--disable-jack \
	--disable-xmms \
	--disable-xdg \
	--disable-debug \
	--disable-profile \
	--disable-static-doc \
	--with-endian=little \
	--with-global-cfg=/opt/etc/quakeforge/quakeforge.conf \
	--with-user-cfg=/opt/etc/quakeforge/.quakeforgerc \
	--with-sharepath=/opt/share/quakeforge \
	--with-userpath=/opt/share/quakeforge \
	--with-servers=master,nq,qw,qtv \
	--with-cpp=$(TARGET_CPP) \
	--without-cd-default \
	--without-clients \
	--without-tools

# You may also compile all possible tools except qfcc (quake C compiler)
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/{hw-master,nq-server,qtv,qw-master,qw-server} $(1)/opt/bin

define Package/quakeforge/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/* $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib/quakeforge/plugins
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/quakeforge/plugins/*.so* $(1)/opt/lib/quakeforge/plugins
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/*.so* $(1)/opt/lib/
	$(INSTALL_DIR) $(1)/opt/share/quakeforge/QF
endef

$(eval $(call BuildPackage,quakeforge))
