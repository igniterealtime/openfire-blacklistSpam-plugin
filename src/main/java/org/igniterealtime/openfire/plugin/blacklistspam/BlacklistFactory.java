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

import org.jivesoftware.util.SystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * A utility method to generate blacklist instances.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class BlacklistFactory
{
    private static final Logger Log = LoggerFactory.getLogger( BlacklistFactory.class );

    /**
     * Timeout to be used when opening a communications link based on the URL from where to obtain the block list.
     */
    public static final SystemProperty<Duration> CONNECTION_CONNECT_TIMEOUT = SystemProperty.Builder.ofType(Duration.class)
        .setKey("blacklistspam.connection.connect.timeout")
        .setPlugin("Spam blacklist")
        .setChronoUnit(ChronoUnit.MILLIS)
        .setDefaultValue(Duration.ofMinutes(1))
        .setDynamic(true)
        .build();

    /**
     * Read timeout to be used when retrieving the block list from the configured URL.
     */
    public static final SystemProperty<Duration> CONNECTION_READ_TIMEOUT = SystemProperty.Builder.ofType(Duration.class)
        .setKey("blacklistspam.connection.read.timeout")
        .setPlugin("Spam blacklist")
        .setChronoUnit(ChronoUnit.MILLIS)
        .setDefaultValue(Duration.ofMinutes(1))
        .setDynamic(true)
        .build();

    /**
     * Value for the 'Content-Type' HTTP request header that is used to read the block list.
     */
    public static final SystemProperty<String> CONNECTION_REQUEST_ACCEPT = SystemProperty.Builder.ofType(String.class)
        .setKey("blacklistspam.connection.request.accept")
        .setPlugin("Spam blacklist")
        .setDefaultValue("text/plain")
        .setDynamic(true)
        .build();

    /**
     * Sets whether HTTP redirects (requests with response code 3xx) should be automatically followed when performing
     * request to read the block list.
     */
    public static final SystemProperty<Boolean> CONNECTION_REQUEST_FOLLOW_REDIRECTS = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("blacklistspam.connection.request.followredirects")
        .setPlugin("Spam blacklist")
        .setDefaultValue(true)
        .setDynamic(true)
        .build();

    /**
     * Creates a blacklist based on the content of a resource obtained via HTTP.
     *
     * Upon a successful HTTP response, it's body is expected to contain a
     * newline-separated list of JIDs.
     *
     * @param url the URL from which to obtain data (cannot be null).
     * @return A blacklist, or null if no blacklist could be constructed.
     */
    public static Blacklist fromURL( URL url )
    {
        if ( url == null )
        {
            throw new IllegalArgumentException( "Argument 'url' cannot be null" );
        }

        try
        {
            Log.debug( "Obtaining blacklist from {}", url );
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod( "GET" );

            con.setConnectTimeout((int) CONNECTION_CONNECT_TIMEOUT.getValue().toMillis());
            con.setReadTimeout((int) CONNECTION_READ_TIMEOUT.getValue().toMillis());
            con.setRequestProperty( "Content-Type", CONNECTION_REQUEST_ACCEPT.getValue() );
            con.setInstanceFollowRedirects( CONNECTION_REQUEST_FOLLOW_REDIRECTS.getValue() );

            final int responseCode = con.getResponseCode();
            final String responseMessage = con.getResponseMessage();
            Log.trace( "HTTP response for GET {} was {} {}", new Object[]{ url, responseCode, responseMessage } );
            if ( responseCode == 204 )
            {
                Log.debug( "HTTP response code was 204: returning an empty blacklist." );
                return new Blacklist( Collections.emptyList() );
            }
            if ( responseCode >= 200 && responseCode <= 299 )
            {
                Log.debug( "Instantiating new blacklist from HTTP response body." );
                final List<String> content = responseAsList( con );
                final Set<JID> jids = asJIDs( content );
                final Blacklist result = new Blacklist( jids );
                return result;
            }
            else if ( responseCode >= 400 && responseCode <= 499 )
            {
                final String response = errorResponseAsText( con );
                Log.error( "The request to obtain a blacklist from {} returned a {} {} response indicating a problem with the request: {}", new Object[]{ url, responseCode, responseMessage, response } );
                return null;
            }
            else if ( responseCode >= 500 )
            {
                final String response = errorResponseAsText( con );
                Log.warn( "The request to obtain a blacklist from {} returned a {} {} response indicating a problem with the remote server: {}", new Object[]{ url, responseCode, responseMessage, response } );
                return null;
            }
            else
            {
                final String response = errorResponseAsText( con );
                Log.warn( "The request to obtain a blacklist from {} returned an unexpected {} {} response: {}", new Object[]{ url, responseCode, responseMessage, response } );
                return null;
            }
        }
        catch ( IOException e )
        {
            Log.warn( "An exception occurred while obtaining a blacklist.", e );
            return null;
        }
    }

    private static List<String> responseAsList( HttpURLConnection con ) throws IOException
    {
        try ( final BufferedReader in = new BufferedReader( new InputStreamReader( con.getInputStream() ) ) )
        {
            final List<String> content = new ArrayList<>();
            String line;
            while ( (line = in.readLine()) != null )
            {
                content.add( line.trim() );
            }
            return content;
        }
    }

    private static String errorResponseAsText( HttpURLConnection con ) throws IOException
    {
        try ( final BufferedReader in = new BufferedReader( new InputStreamReader( con.getErrorStream() ) ) )
        {
            final StringBuilder content = new StringBuilder();
            String line;
            while ( (line = in.readLine()) != null )
            {
                content.append( line );
            }
            return content.toString();
        }
    }

    private static Set<JID> asJIDs( Collection<String> content )
    {
        if ( content == null )
        {
            throw new IllegalArgumentException( "Argument 'content' cannot be null." );
        }

        final Set<JID> result = new HashSet<>();
        for ( final String line : content )
        {
            try
            {
                final JID jid = new JID( line );
                result.add( jid );
            }
            catch ( Exception e )
            {
                Log.debug( "Unable to parse JID from {}. Skipping value.", line, e );
            }
        }

        return result;
    }
}
