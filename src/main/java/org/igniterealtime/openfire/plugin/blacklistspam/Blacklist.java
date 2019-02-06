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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An immutable collection of unique JIDs, with additional functionality that
 * facilitates blacklisting features.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class Blacklist
{
    private final static Logger Log = LoggerFactory.getLogger( Blacklist.class );

    private final Set<String> blacklist; // uses Strings instead of JIDs which is thought to improve performance.

    /**
     * Constructs a new collection.
     *
     * @param blacklist A collection of JIDs. Cannot be null, can be empty.
     */
    public Blacklist( Collection<JID> blacklist )
    {
        if ( blacklist == null )
        {
            throw new IllegalArgumentException( "Argument 'blacklist' cannot be null." );
        }

        this.blacklist = blacklist.parallelStream().map( JID::toString ).collect( Collectors.toSet() );
        Log.debug( "Constructed a new blacklist with {} JIDs.", this.blacklist.size() );
    }

    /**
     * Verifies if the provided JID matches at least one entry in this
     * collection. A match is said to occur when the collection contains either
     *
     * <ul>
     *   <li>the provided JID;</li>
     *   <li>the domain-part of the provided JID;</li>
     *   <li>the bare JID representation of the provided JID.</li>
     * </ul>
     *
     * @param jid The value to check (cannot be null).
     * @return True if the value is in the collection, otherwise false.
     */
    public boolean isOnBlacklist( final JID jid )
    {
        final boolean result = blacklist.contains( jid.toString() ) || blacklist.contains( jid.getDomain() ) || blacklist.contains( jid.toBareJID() );
        Log.trace( "JID {} on blacklist: {}", jid, result );
        return result;
    }
}
