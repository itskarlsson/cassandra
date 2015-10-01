/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cassandra.auth;

import java.lang.management.ManagementFactory;
import java.util.Set;

import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

import com.google.common.collect.Sets;

public class JMXResource implements IResource
{
    enum Level
    {
        ROOT, MBEAN
    }

    private static final String ROOT_NAME = "mbean";
    private static final JMXResource ROOT_RESOURCE = new JMXResource();
    private final Level level;
    private final String name;

    // permissions which may be granted on Mbeans
    private static final Set<Permission> JMX_PERMISSIONS = Sets.immutableEnumSet(Permission.MBEXECUTE,
                                                                                 Permission.MBGET,
                                                                                 Permission.MBSET,
                                                                                 Permission.MBINSTANCEOF,
                                                                                 Permission.MBINVOKE,
                                                                                 Permission.MBQUERYNAMES,
                                                                                 Permission.MBREAD,
                                                                                 Permission.MBWRITE,
                                                                                 Permission.AUTHORIZE);

    private JMXResource()
    {
        level = Level.ROOT;
        name = null;
    }

    private JMXResource(String name)
    {
        this.name = name;
        level = Level.MBEAN;
    }

    public static JMXResource mbean(String name)
    {
        return new JMXResource(name);
    }

    @Override
    public String getName()
    {
        if (level == Level.ROOT)
            return ROOT_NAME;
        else if (level == Level.MBEAN)
            return String.format("%s/%s", ROOT_NAME, name);
        throw new AssertionError();
    }

    /**
     * @return the root-level resource.
     */
    public static JMXResource root()
    {
        return ROOT_RESOURCE;
    }

    @Override
    public IResource getParent()
    {
        if (level == Level.MBEAN)
            return root();
        throw new IllegalStateException("Root-level resource can't have a parent");
    }

    /**
     * @return Whether or not the resource has a parent in the hierarchy.
     */
    @Override
    public boolean hasParent()
    {
        return !level.equals(Level.ROOT);
    }

    @Override
    public boolean exists()
    {
        if (!hasParent())
            return true;
        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
        try
        {
            return !(mbs.queryNames(new ObjectName(name), null).isEmpty());
        }
        catch (MalformedObjectNameException e)
        {
            return false;
        }
        catch (NullPointerException e)
        {
            return false;
        }
    }

    @Override
    public Set<Permission> applicablePermissions()
    {
        return JMX_PERMISSIONS;
    }
}
