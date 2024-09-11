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
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.util.SystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Timer;
import java.util.TimerTask;

/**
 * An Openfire plugin that rejects stanzas based on their addressing. Stanza
 * addresses are compared to a list of JIDs that is periodically retrieved from
 * an HTTP endpoint.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class BlacklistSpamPlugin implements Plugin
{
    private static final Logger Log = LoggerFactory.getLogger( BlacklistSpamPlugin.class );

    /**
     * URL from where to obtain the block list, a plain-text body, with JIDs (domains) separated by newlines (one JID per line).
     */
    public static final SystemProperty<String> CONNECTION_CONNECT_REQUEST_URL = SystemProperty.Builder.ofType(String.class)
        .setKey("blacklistspam.connection.request.url")
        .setPlugin("Spam blacklist")
        .setDefaultValue("https://igniterealtime.org/JabberSPAM/blacklist.txt")
        .setDynamic(true)
        .build();

    /**
     * The frequency in which to retrieve and refresh the block list.
     */
    public static final SystemProperty<Duration> REFRESH_INTERVAL = SystemProperty.Builder.ofType(Duration.class)
        .setKey("blacklistspam.refresh.interval")
        .setPlugin("Spam blacklist")
        .setChronoUnit(ChronoUnit.MILLIS)
        .setDefaultValue(Duration.ofDays(1))
        .setDynamic(true)
        .addListener((v) -> ((BlacklistSpamPlugin) XMPPServer.getInstance().getPluginManager().getPluginByName("Spam blacklist").orElseThrow()).rescheduleTask())
        .build();

    private StanzaBlocker stanzaBlocker;
    private Timer timer;

    @Override
    public synchronized void initializePlugin( final PluginManager manager, final File pluginDirectory )
    {
        stanzaBlocker = new StanzaBlocker();
        InterceptorManager.getInstance().addInterceptor( stanzaBlocker );
        rescheduleTask();
    }

    @Override
    public synchronized void destroyPlugin()
    {
        if ( stanzaBlocker != null )
        {
            InterceptorManager.getInstance().removeInterceptor( stanzaBlocker );
        }

        if ( timer != null )
        {
            timer.cancel();
            timer = null;
        }
    }

    public synchronized void rescheduleTask()
    {
        if ( timer != null )
        {
            timer.cancel();
            timer = null;
        }

        timer = new Timer();
        timer.schedule( new TimerTask()
        {
            @Override
            public void run()
            {
                final String urlValue = CONNECTION_CONNECT_REQUEST_URL.getValue();
                try
                {
                    final URL url = new URL( urlValue );
                    final Blacklist blacklist = BlacklistFactory.fromURL( url );
                    if ( blacklist != null )
                    {
                        stanzaBlocker.setBlacklist( blacklist );
                        Log.info( "Refreshed blacklist from {}", url );
                    }
                    else
                    {
                        Log.warn( "Failed to refresh blacklist from {}.", url );
                    }
                }
                catch ( MalformedURLException e )
                {
                    Log.error( "Unable to parse value as URL: {}.", urlValue, e );
                }
            }
        },
            0,
            REFRESH_INTERVAL.getValue().toMillis()
        );
    }

    public StanzaBlocker getStanzaBlocker() {
        return stanzaBlocker;
    }
}
