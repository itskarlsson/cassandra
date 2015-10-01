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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;

/**
 * This LoginModule authenticates a user towards the Cassandra database.
 */
public class CassandraLoginModule implements LoginModule
{

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    // username and password
    private String username;
    private char[] password;

    // testUser's SamplePrincipal
    private CassandraPrincipal userPrincipal;

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * <p>
     *
     * @param subject the <code>Subject</code> to be authenticated. <p>
     *
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *                  with the end user (prompting for user names and
     *                  passwords, for example). <p>
     *
     * @param sharedState shared <code>LoginModule</code> state. <p>
     *
     * @param options options specified in the login
     *                  <code>Configuration</code> for this particular
     *                  <code>LoginModule</code>.
     */
    @Override
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<java.lang.String, ?> sharedState,
                           Map<java.lang.String, ?> options)
    {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
    }

    /**
     * Authenticate the user by prompting for a user name and password.
     *
     * <p>
     *
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.
     *
     * @exception FailedLoginException if the authentication fails. <p>
     *
     * @exception LoginException if this <code>LoginModule</code>
     *          is unable to perform the authentication.
     */
    @Override
    public boolean login() throws LoginException
    {
        // prompt for a user name and password
        if (callbackHandler == null)
            throw new LoginException("Error: no CallbackHandler available " +
                    "to garner authentication information from the user");

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("user name: ");
        callbacks[1] = new PasswordCallback("password: ", false);

        try
        {
            callbackHandler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();
            char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
            if (tmpPassword == null)
            {
                // treat a NULL password as an empty password
                tmpPassword = new char[0];
            }
            password = new char[tmpPassword.length];
            System.arraycopy(tmpPassword, 0,
                    password, 0, tmpPassword.length);
            ((PasswordCallback) callbacks[1]).clearPassword();

        }
        catch (IOException ioe)
        {
            throw new LoginException(ioe.toString());
        }
        catch (UnsupportedCallbackException uce)
        {
            throw new LoginException("Error: " + uce.getCallback().toString() +
                    " not available to garner authentication information " +
                    "from the user");
        }

        // verify the credentials
        Map<String, String> credentials = new HashMap<String, String>();
        credentials.put("password", String.valueOf(password));
        credentials.put("username", username);
        IAuthenticator authenticator = DatabaseDescriptor.getAuthenticator();
        try
        {
            authenticator.legacyAuthenticate(credentials);
        }
        catch (AuthenticationException e)
        {
            // authentication failed -- clean up
            succeeded = false;
            username = null;
            for (int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
            throw new FailedLoginException("Username and/or Password incorrect");
        }

        succeeded = true;
        return true;
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * succeeded).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method associates a
     * <code>CassPrincipal</code>
     * with the <code>Subject</code> located in the
     * <code>LoginModule</code>.  If this LoginModule's own
     * authentication attempted failed, then this method removes
     * any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the commit fails.
     *
     * @return true if this LoginModule's own login and commit
     *          attempts succeeded, or false otherwise.
     */
    @Override
    public boolean commit() throws LoginException
    {
        if (succeeded == false)
        {
            return false;
        }
        else
        {
            // add a Principal (authenticated identity)
            // to the Subject

            userPrincipal = new CassandraPrincipal(username);
            if (!subject.getPrincipals().contains(userPrincipal))
                subject.getPrincipals().add(userPrincipal);

            // clean out state
            username = null;
            for (int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;

            commitSucceeded = true;
            return true;
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * did not succeed).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> and <code>commit</code> methods),
     * then this method cleans up any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the abort fails.
     *
     * @return false if this LoginModule's own login and/or commit attempts
     *          failed, and true otherwise.
     */
    @Override
    public boolean abort() throws LoginException
    {
        if (succeeded == false)
        {
            return false;
        }
        else if (commitSucceeded == false)
        {
            // login succeeded but overall authentication failed
            succeeded = false;
            username = null;
            if (password != null)
            {
                for (int i = 0; i < password.length; i++)
                    password[i] = ' ';
                password = null;
            }
            userPrincipal = null;
        }
        else
        {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * Logout the user.
     *
     * <p> This method removes the principal
     * that was added by the <code>commit</code> method.
     *
     * <p>
     *
     * @exception LoginException if the logout fails.
     *
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.
     */
    @Override
    public boolean logout() throws LoginException
    {
        subject.getPrincipals().remove(userPrincipal);
        succeeded = false;
        username = null;
        if (password != null)
        {
            for (int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
        }
        userPrincipal = null;
        return true;
    }
}
