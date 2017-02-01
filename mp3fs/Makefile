#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It's painfully slow for MIPS devices, also, it hangs until whole track is transcoding

include $(TOPDIR)/rules.mk

PKG_NAME:=mp3fs
PKG_VERSION:=0.31
PKG_RELEASE:=1

PKG_REV:=ad2145546360a7478fbdf256176ff5436405c1d5
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/dbrashear/mp3fs.git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/mp3fs
	SECTION:=multimedia
	CATEGORY:=Multimedia
	DEPENDS:=+libflac +libfuse +libid3tag +lame-lib
	TITLE:=transcoding filesystem from FLAC to MP3
	URL:=http://khenriks.github.com/mp3fs/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/mp3fs/description
 MP3FS is a read-only FUSE filesystem which transcodes audio formats (currently
 FLAC) to MP3 on the fly when opened and read. This was written to enable me to
 use my FLAC collection with software and/or hardware which only understands the
 MP3 format. It is also a novel alternative to traditional MP3 encoders.
endef

CONFIGURE_VARS += \
	id3tag_LIBS="-lid3tag -L$(STAGING_DIR)/opt/lib" \
	id3tag_CFLAGS="-I$(STAGING_DIR)/opt/include" \

define Package/mp3fs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/mp3fs $(1)/opt/bin/
endef

$(eval $(call BuildPackage,mp3fs))
