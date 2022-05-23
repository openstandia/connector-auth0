/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.auth0;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

public class Auth0Configuration extends AbstractConfiguration {

    private String domain;
    private String clientId;
    private GuardedString clientSecret;
    private Integer connectionTimeoutInSeconds = 10;
    private Integer readTimeoutInSeconds = 10;
    private Integer maxRetries = 3;
    private String httpProxyHost;
    private int httpProxyPort;
    private String httpProxyUser;
    private GuardedString httpProxyPassword;
    private Integer defaultQueryPageSize = 50;
    private String[] databaseConnection = new String[]{"Username-Password-Authentication"};

    @ConfigurationProperty(
            order = 1,
            displayMessageKey = "Auth0 Domain",
            helpMessageKey = "Auth0 domain which is connected from this connector.",
            required = true,
            confidential = false)
    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    @ConfigurationProperty(
            order = 2,
            displayMessageKey = "Auth0 Client ID",
            helpMessageKey = "Set your Auth0 API Client ID to connect Auth0.",
            required = false,
            confidential = false)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String apiToken) {
        this.clientId = apiToken;
    }

    @ConfigurationProperty(
            order = 3,
            displayMessageKey = "Auth0 Client Secret",
            helpMessageKey = "Set your Auth0 API Client Secret to connect Auth0.",
            required = false,
            confidential = true)
    public GuardedString getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(GuardedString clientSecret) {
        this.clientSecret = clientSecret;
    }

    @ConfigurationProperty(
            order = 4,
            displayMessageKey = "Database Connections",
            helpMessageKey = "Set database connections. Default: Username-Password-Authentication",
            required = true,
            confidential = false)
    public String[] getDatabaseConnection() {
        return databaseConnection;
    }

    public void setDatabaseConnection(String[] databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    @ConfigurationProperty(
            order = 10,
            displayMessageKey = "Connection Timeout (in seconds)",
            helpMessageKey = "Connection timeout when connecting to Auth0. (Default: 10)",
            required = false,
            confidential = false)
    public Integer getConnectionTimeoutInSeconds() {
        return connectionTimeoutInSeconds;
    }

    public void setConnectionTimeoutInSeconds(Integer connectionTimeoutInSeconds) {
        this.connectionTimeoutInSeconds = connectionTimeoutInSeconds;
    }

    @ConfigurationProperty(
            order = 11,
            displayMessageKey = "Read Timeout (in seconds)",
            helpMessageKey = "Read timeout when fetching data from Auth0. (Default: 10)",
            required = false,
            confidential = false)
    public Integer getReadTimeoutInSeconds() {
        return readTimeoutInSeconds;
    }

    public void setReadTimeoutInSeconds(Integer readTimeoutInSeconds) {
        this.readTimeoutInSeconds = readTimeoutInSeconds;
    }

    @ConfigurationProperty(
            order = 12,
            displayMessageKey = "Max Retries",
            helpMessageKey = "Sets the maximum number of consecutive retries for Auth0 Management API requests that fail due to rate-limits being reached. (Default: 3)",
            required = false,
            confidential = false)
    public Integer getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
    }

    @ConfigurationProperty(
            order = 13,
            displayMessageKey = "HTTP Proxy Host",
            helpMessageKey = "Hostname for the HTTP Proxy",
            required = false,
            confidential = false)
    public String getHttpProxyHost() {
        return httpProxyHost;
    }

    public void setHttpProxyHost(String httpProxyHost) {
        this.httpProxyHost = httpProxyHost;
    }

    @ConfigurationProperty(
            order = 14,
            displayMessageKey = "HTTP Proxy Port",
            helpMessageKey = "Port for the HTTP Proxy",
            required = false,
            confidential = false)
    public int getHttpProxyPort() {
        return httpProxyPort;
    }

    public void setHttpProxyPort(int httpProxyPort) {
        this.httpProxyPort = httpProxyPort;
    }

    @ConfigurationProperty(
            order = 15,
            displayMessageKey = "HTTP Proxy User",
            helpMessageKey = "Username for the HTTP Proxy Authentication",
            required = false,
            confidential = false)
    public String getHttpProxyUser() {
        return httpProxyUser;
    }

    public void setHttpProxyUser(String httpProxyUser) {
        this.httpProxyUser = httpProxyUser;
    }

    @ConfigurationProperty(
            order = 16,
            displayMessageKey = "HTTP Proxy Password",
            helpMessageKey = "Password for the HTTP Proxy Authentication",
            required = false,
            confidential = true)
    public GuardedString getHttpProxyPassword() {
        return httpProxyPassword;
    }

    public void setHttpProxyPassword(GuardedString httpProxyPassword) {
        this.httpProxyPassword = httpProxyPassword;
    }

    @ConfigurationProperty(
            order = 17,
            displayMessageKey = "Default Query Page Size",
            helpMessageKey = "Set default query page size. Default: 50",
            required = false,
            confidential = false)
    public Integer getDefaultQueryPageSize() {
        return defaultQueryPageSize;
    }

    public void setDefaultQueryPageSize(Integer defaultQueryPageSize) {
        this.defaultQueryPageSize = defaultQueryPageSize;
    }

    @Override
    public void validate() {
    }
}
