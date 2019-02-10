/*
 * Copyright 2019 Ignite Realtime Foundation
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

import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventListener;
import org.xmpp.packet.Packet;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A {@link PacketInterceptor} that rejects stanzas, based on a blacklist.
 * <p>
 * Upon construction of a new instance no blacklist is defined, and no stanzas
 * will be blocked.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class StanzaBlocker implements PacketInterceptor, PropertyEventListener
{
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
            if ( blacklist != null
                && ((checkIncoming && incoming) || (checkOutgoing && processed))
                && blacklist.isOnBlacklist( packet.getFrom() )
            )
            {
                throw new PacketRejectedException( "Rejected packet sent by entity '" + packet.getFrom() + "' that is on the blacklist." );
            }
        }
        finally
        {
            rwl.readLock().unlock();
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
    protected void refreshPropertyValues()
    {
        rwl.writeLock().lock();
        try
        {
            checkIncoming = JiveGlobals.getBooleanProperty( "blacklistspam.check.incoming", true );
            checkOutgoing = JiveGlobals.getBooleanProperty( "blacklistspam.check.outgoing", false );
        }
        finally
        {
            rwl.writeLock().unlock();
        }
    }

    @Override
    public void propertySet( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.check.incoming", "blacklistspam.check.outgoing" ).contains( property ) )
        {
            refreshPropertyValues();
        }
    }

    @Override
    public void propertyDeleted( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.check.incoming", "blacklistspam.check.outgoing" ).contains( property ) )
        {
            refreshPropertyValues();
        }
    }

    @Override
    public void xmlPropertySet( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.check.incoming", "blacklistspam.check.outgoing" ).contains( property ) )
        {
            refreshPropertyValues();
        }
    }

    @Override
    public void xmlPropertyDeleted( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.check.incoming", "blacklistspam.check.outgoing" ).contains( property ) )
        {
            refreshPropertyValues();
        }
    }
}
