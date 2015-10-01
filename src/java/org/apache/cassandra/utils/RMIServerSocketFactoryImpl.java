package org.apache.cassandra.utils;

import java.io.IOException;
import java.net.*;
import java.rmi.server.RMIServerSocketFactory;

import javax.net.ServerSocketFactory;

public class RMIServerSocketFactoryImpl implements RMIServerSocketFactory
{
    public final static String ALL_INTERFACES = "0.0.0.0";
    private String host;
    private Boolean allInterfaces = false;

    public RMIServerSocketFactoryImpl(String host)
    {
        if (host.equals(ALL_INTERFACES))
        {
            this.allInterfaces = true;
        }
        else
        {
            this.host = host;
        }
    }

    public RMIServerSocketFactoryImpl()
    {
        this.host = null;
    }

    public ServerSocket createServerSocket(final int pPort) throws IOException
    {
        if(allInterfaces)
            return ServerSocketFactory.getDefault().createServerSocket(pPort, 0, null);
        return ServerSocketFactory.getDefault().createServerSocket(pPort, 0, InetAddress.getByName(host));
    }

    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (obj == this)
        {
            return true;
        }

        return obj.getClass().equals(getClass());
    }

    public int hashCode()
    {
        return RMIServerSocketFactoryImpl.class.hashCode();
    }
}
