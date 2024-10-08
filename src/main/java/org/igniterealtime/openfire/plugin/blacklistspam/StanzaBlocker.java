/*
 * Copyright 2019-2024 Ignite Realtime Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.igniterealtime.openfire.plugin.blacklistspam;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.SystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.Packet;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A {@link PacketInterceptor} that rejects stanzas, based on a blacklist.
 * <p>
 * Upon construction of a new instance no blacklist is defined, and no stanzas
 * will be blocked.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class StanzaBlocker implements PacketInterceptor
{
    private static final Logger Log = LoggerFactory.getLogger( StanzaBlocker.class );

    /**
     * Store blocked stanzas in a file on disk.
     */
    public static final SystemProperty<Boolean> BLOCKEDLOG_ENABLED = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("blacklistspam.blockedlog.enabled")
        .setPlugin("Spam blacklist")
        .setDefaultValue(false)
        .setDynamic(true)
        .build();

    /**
     * Verify stanzas that are inbound (being sent to the server).
     */
    public static final SystemProperty<Boolean> CHECK_INCOMING = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("blacklistspam.check.incoming")
        .setPlugin("Spam blacklist")
        .setDefaultValue(true)
        .setDynamic(true)
        .addListener((v) -> ((BlacklistSpamPlugin) XMPPServer.getInstance().getPluginManager().getPluginByName("Spam blacklist").orElseThrow()).getStanzaBlocker().refreshPropertyValues())
        .build();

    /**
     * Verify stanzas that are outbound (being sent from the server).
     */
    public static final SystemProperty<Boolean> CHECK_OUTGOING = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("blacklistspam.check.outgoing")
        .setPlugin("Spam blacklist")
        .setDefaultValue(false)
        .setDynamic(true)
        .addListener((v) -> ((BlacklistSpamPlugin) XMPPServer.getInstance().getPluginManager().getPluginByName("Spam blacklist").orElseThrow()).getStanzaBlocker().refreshPropertyValues())
        .build();

    private Blacklist blacklist;

    private boolean checkIncoming;
    private boolean checkOutgoing;

    private final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();

    public StanzaBlocker()
    {
        refreshPropertyValues();
    }

    @Override
    public void interceptPacket( final Packet packet, final Session session, final boolean incoming, final boolean processed ) throws PacketRejectedException
    {
        rwl.readLock().lock();
        try
        {
            if ( blacklist != null && packet.getFrom() != null
                && ((checkIncoming && incoming) || (checkOutgoing && processed))
                && blacklist.isOnBlacklist( packet.getFrom() )
            )
            {
                Log.info( "Rejected stanza sent by entity '{}' that is on the blacklist.", packet.getFrom() );
                try {
                    if ( BLOCKEDLOG_ENABLED.getValue() ) {
                        store(packet);
                    }
                } catch ( final Exception e ) {
                    Log.warn( "An unexpected exception occurred while trying to store a rejected stanza.", e );
                }
                throw new PacketRejectedException( "Rejected stanza sent by entity '" + packet.getFrom() + "' that is on the blacklist." );
            }
        }
        finally
        {
            rwl.readLock().unlock();
        }
    }

    /**
     * Stores a stanza in a text file. This is intended to facilitate future analysis of spam.
     *
     * @param stanza The stanza to be stored (cannot be null).
     */
    public void store( final Packet stanza )
    {
        final Path logDir = JiveGlobals.getHomePath().resolve("blacklist").resolve("blocked");
        final Instant now = Instant.now();
        final String fileName = DateTimeFormatter.BASIC_ISO_DATE.withZone(ZoneId.systemDefault()).format(now).concat(".txt" );
        final String data = DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.systemDefault()).format(now) + " from [" + stanza.getFrom() + "]: " + stanza.toXML() + System.lineSeparator();

        try {
            Files.createDirectories( logDir );
            Files.write( logDir.resolve( fileName ), data.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND );
        } catch ( final Exception e ) {
            Log.warn( "An exception occurred while attempting to store blocked stanza to file.", e );
        }
    }

    /**
     * Replaces the current blacklist (if any) with a new instance.
     * <p>
     * This method is thread-safe.
     *
     * @param blacklist Blacklist, can be null.
     */
    public void setBlacklist( final Blacklist blacklist )
    {
        rwl.writeLock().lock();
        this.blacklist = blacklist;
        rwl.writeLock().unlock();
    }

    /**
     * Resets all values that are obtained through properties.
     */
    public void refreshPropertyValues()
    {
        rwl.writeLock().lock();
        try
        {
            checkIncoming = CHECK_INCOMING.getValue();
            checkOutgoing = CHECK_OUTGOING.getValue();
        }
        finally
        {
            rwl.writeLock().unlock();
        }
    }
}
