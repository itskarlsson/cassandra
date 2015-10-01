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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.Set;

import javax.management.MBeanServer;
import javax.management.remote.MBeanServerForwarder;
import javax.security.auth.Subject;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.utils.FBUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JMXCassandraAuthorizer implements InvocationHandler
{
    private static final Logger logger = LoggerFactory.getLogger(JMXCassandraAuthorizer.class);

    private MBeanServer mbs;

    // Expect non null parameter
    public static MBeanServerForwarder newProxyInstance(String authclassname)
    {
        try
        {
            final InvocationHandler handler = FBUtilities.construct(authclassname, "MBeanServerForwarder");

            final Class[] interfaces =
                    new Class[]
                    { MBeanServerForwarder.class };

            Object proxy = Proxy.newProxyInstance(
                    MBeanServerForwarder.class.getClassLoader(),
                    interfaces,
                    handler);

            return MBeanServerForwarder.class.cast(proxy);
        }
        catch (ConfigurationException e)
        {
            logger.error("Could not create MBeanServerForwarder", e);
        }

        return null;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args)
            throws Throwable
    {
        final IAuthorizer authorizer = DatabaseDescriptor.getAuthorizer();

        final String methodName = method.getName();
        // Retrieve Subject from current AccessControlContext
        AccessControlContext acc = AccessController.getContext();
        Subject subject = Subject.getSubject(acc);

        if (("getMBeanServer").equals(methodName))
        {
            throw new SecurityException("Access denied");
        }

        // Allow operation only if performed on behalf of the connector server itself
        if (("setMBeanServer").equals(methodName) && subject == null)
        {
            if (args[0] == null)
                throw new IllegalArgumentException("Null MBeanServer");
            if (mbs != null)
                throw new IllegalArgumentException("MBeanServer object " +
                        "already initialized");
            mbs = (MBeanServer) args[0];
            return null;
        }
        if (authorizer instanceof AllowAllAuthorizer)
            return invoke(method, args);

        // Allow operations performed locally on behalf of the connector server itself
        if (subject == null)
        {
            return invoke(method, args);
        }

        // Restrict access to "createMBean" and "unregisterMBean" to any user
        if (("createMBean").equals(methodName) || ("unregisterMBean").equals(methodName))
        {
            throw new SecurityException("Access denied");
        }

        Set<Principal> principals = subject.getPrincipals();
        if (principals == null || principals.isEmpty())
        {
            throw new SecurityException("Access denied");
        }
        Principal principal = principals.iterator().next();
        String identity = principal.getName();
        Set<Permission> permissions;
        if (args == null || args[0] == null)
        {
            permissions = Permission.ALL_JMX;
        }
        else
        {
            permissions = authorizer.authorizeJMX(new AuthenticatedUser(identity), JMXResource.mbean(args[0].toString()));
        }

        switch (methodName)
        {
            case "isRegistered":
            case "getMBeanInfo":
            case "getDefaultDomain":
            case "getDomains":
            case "hashCode":
            case "getAttribute":
            case "getAttributes":
                if (permissions.contains(Permission.MBGET) || permissions.contains(Permission.MBREAD))
                    return invoke(method, args);
                break;
            case "setAttribute":
            case "setAttributes":
                if (permissions.contains(Permission.MBSET) || permissions.contains(Permission.MBWRITE))
                    return invoke(method, args);
                break;
            case "invoke":
                if (permissions.contains(Permission.MBINVOKE) || permissions.contains(Permission.MBEXECUTE))
                    return invoke(method, args);
                break;
            case "isInstanceOf":
                if (permissions.contains(Permission.MBINSTANCEOF) || permissions.contains(Permission.MBREAD) || permissions.contains(Permission.MBWRITE))
                    return invoke(method, args);
                break;
            case "queryNames":
                if (permissions.contains(Permission.MBQUERYNAMES) || permissions.contains(Permission.MBREAD))
                    return invoke(method, args);
                break;
        }

        throw new SecurityException("Access Denied");
    }

    private Object invoke(Method method, Object[] args) throws IllegalAccessException, Throwable
    {
        try
        {
            Object o = method.invoke(mbs, args);
            return o;
        }
        catch (InvocationTargetException e) //Catch any exception that might have been thrown by the mbeans
        {
            Throwable t = e.getCause(); //Throw the exception that nodetool expects
            throw t;
        }
    }
}
