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

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

/**
 * An Openfire plugin that rejects stanzas based on the their addressing. Stanza
 * addresses are compared to a list of JIDs that is periodically retrieved from
 * a HTTP endpoint.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class BlacklistSpamPlugin implements Plugin, PropertyEventListener
{
    private static final Logger Log = LoggerFactory.getLogger( BlacklistSpamPlugin.class );

    private StanzaBlocker stanzaBlocker;
    private Timer timer;

    @Override
    public synchronized void initializePlugin( final PluginManager manager, final File pluginDirectory )
    {
        stanzaBlocker = new StanzaBlocker();
        PropertyEventDispatcher.addListener( stanzaBlocker );
        InterceptorManager.getInstance().addInterceptor( stanzaBlocker );
        PropertyEventDispatcher.addListener( this );
        rescheduleTask();
    }

    @Override
    public synchronized void destroyPlugin()
    {
        PropertyEventDispatcher.removeListener( this );

        if ( stanzaBlocker != null )
        {
            InterceptorManager.getInstance().removeInterceptor( stanzaBlocker );
            PropertyEventDispatcher.removeListener( stanzaBlocker );
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
                final String urlValue = JiveGlobals.getProperty( "blacklistspam.connection.request.url", "https://igniterealtime.org/JabberSPAM/blacklist.txt" );
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
            JiveGlobals.getLongProperty( "blacklistspam.refresh.interval", TimeUnit.DAYS.toMillis( 1 ) )
        );
    }

    @Override
    public void propertySet( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.refresh.interval" ).contains( property ) )
        {
            rescheduleTask();
        }
    }

    @Override
    public void propertyDeleted( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.refresh.interval" ).contains( property ) )
        {
            rescheduleTask();
        }
    }

    @Override
    public void xmlPropertySet( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.refresh.interval" ).contains( property ) )
        {
            rescheduleTask();
        }
    }

    @Override
    public void xmlPropertyDeleted( final String property, final Map<String, Object> params )
    {
        if ( Arrays.asList( "blacklistspam.refresh.interval" ).contains( property ) )
        {
            rescheduleTask();
        }
    }
}
