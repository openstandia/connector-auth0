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

import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.organizations.Branding;
import com.auth0.json.mgmt.organizations.Colors;
import com.auth0.json.mgmt.organizations.Organization;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.util.Map;
import java.util.Set;

import static jp.openstandia.connector.auth0.Auth0Utils.*;

public class Auth0OrganizationHandler {

    public static final ObjectClass ORGANIZATION_OBJECT_CLASS = new ObjectClass("Organization");

    private static final Log LOGGER = Log.getLog(Auth0OrganizationHandler.class);

    // Unique and unchangeable
    private static final String ATTR_ORGANIZATION_ID = "orgId";

    // Unique and changeable
    // "Name" must only contain lowercase characters, '-', and '_', and start with a letter or number.
    private static final String ATTR_ORGANIZATION_NAME = "name";

    // Attributes
    private static final String ATTR_DISPLAY_NAME = "display_name";
    private static final String ATTR_BRANDING_LOG_URL = "branding.logo_url";
    private static final String ATTR_BRANDING_COLORS_PRIMARY = "branding.colors.primary";
    private static final String ATTR_BRANDING_COLORS_PAGE_BACKGROUND = "branding.colors.page_background";

    // Association
    // Nothing

    private final Auth0Configuration configuration;
    private final Auth0Client client;
    private final Map<String, AttributeInfo> schema;
    private final Auth0AssociationHandler associationHandler;

    public Auth0OrganizationHandler(Auth0Configuration configuration, Auth0Client client, Map<String, AttributeInfo> schema) {
        this.configuration = configuration;
        this.client = client;
        this.schema = schema;
        this.associationHandler = new Auth0AssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getSchema(Auth0Configuration config) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(ORGANIZATION_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(true)
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_ORGANIZATION_ID)
                .build());
        // __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .setNativeName(ATTR_ORGANIZATION_NAME)
                .build());

        // Standard Attributes
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DISPLAY_NAME)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_BRANDING_LOG_URL)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_BRANDING_COLORS_PRIMARY)
                .build());
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_BRANDING_COLORS_PAGE_BACKGROUND)
                .build());

        ObjectClassInfo organizationSchemaInfo = builder.build();

        LOGGER.info("The constructed Organization schema: {0}", organizationSchemaInfo);

        return organizationSchemaInfo;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2#!/Organizations/post_organizations
     *
     * @param attributes
     * @return
     * @throws Auth0Exception
     */
    public Uid create(Set<Attribute> attributes) throws Auth0Exception {
        Organization newOrg = new Organization();
        Branding branding = null;
        Colors colors = null;

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newOrg.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_DISPLAY_NAME)) {
                newOrg.setDisplayName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_BRANDING_LOG_URL)) {
                if (branding == null) {
                    branding = new Branding();
                }
                branding.setLogoUrl(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_BRANDING_COLORS_PRIMARY)) {
                if (branding == null) {
                    branding = new Branding();
                }
                if (colors == null) {
                    colors = new Colors();
                    branding.setColors(colors);
                }
                colors.setPrimary(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_BRANDING_COLORS_PAGE_BACKGROUND)) {
                if (branding == null) {
                    branding = new Branding();
                }
                if (colors == null) {
                    colors = new Colors();
                    branding.setColors(colors);
                }
                colors.setPageBackground(AttributeUtil.getAsStringValue(attr));

            } else {
                throwInvalidSchema(attr.getName());
            }
        }

        if (branding != null) {
            newOrg.setBranding(branding);
        }

        Organization response = client.createOrganization(newOrg);

        Uid newUid = new Uid(response.getId(), new Name(response.getName()));

        return newUid;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2#!/Organizations/patch_organizations_by_id
     *
     * @param uid
     * @param modifications
     * @param options
     * @return
     * @throws Auth0Exception
     */
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws Auth0Exception {
        Organization patchOrg = new Organization();
        Branding branding = null;
        Colors colors = null;

        for (AttributeDelta delta : modifications) {
            if (delta.getName().equals(Name.NAME)) {
                patchOrg.setName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_DISPLAY_NAME)) {
                patchOrg.setDisplayName(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_BRANDING_LOG_URL)) {
                if (branding == null) {
                    branding = new Branding();
                }
                branding.setLogoUrl(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_BRANDING_COLORS_PRIMARY)) {
                if (branding == null) {
                    branding = new Branding();
                }
                if (colors == null) {
                    colors = new Colors();
                    branding.setColors(colors);
                }
                colors.setPrimary(AttributeDeltaUtil.getAsStringValue(delta));

            } else if (delta.getName().equals(ATTR_BRANDING_COLORS_PAGE_BACKGROUND)) {
                if (branding == null) {
                    branding = new Branding();
                }
                if (colors == null) {
                    colors = new Colors();
                    branding.setColors(colors);
                }
                colors.setPageBackground(AttributeDeltaUtil.getAsStringValue(delta));

            } else {
                throwInvalidSchema(delta.getName());
            }
        }

        if (branding != null) {
            patchOrg.setBranding(branding);
        }

        client.updateOrganization(uid, patchOrg);

        return null;
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2#!/Organizations/delete_organizations_by_id
     *
     * @param uid
     * @param options
     * @throws Auth0Exception
     */
    public void delete(Uid uid, OperationOptions options) throws Auth0Exception {
        client.deleteOrganization(uid);
    }

    /**
     * The spec:
     * https://auth0.com/docs/api/management/v2#!/Organizations/get_organizations
     *
     * @param filter
     * @param resultsHandler
     * @param options
     * @throws Auth0Exception
     */
    public void query(Auth0Filter filter,
                      ResultsHandler resultsHandler, OperationOptions options) throws Auth0Exception {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema, options);
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        if (filter != null) {
            if (filter.isByName()) {
                // Filter by __NANE__
                getOrganizationByName(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            } else {
                // Filter by __UID__
                getOrganizationByUid(filter.attributeValue, resultsHandler, attributesToGet, allowPartialAttributeValues);
            }
            return;
        }

        client.getOrganizations(options, (org) -> resultsHandler.handle(toConnectorObject(org, attributesToGet, allowPartialAttributeValues)));
    }

    private void getOrganizationByName(String orgName,
                                       ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        Organization org = client.getOrganizationByName(orgName);

        resultsHandler.handle(toConnectorObject(org, attributesToGet, allowPartialAttributeValues));
    }

    private void getOrganizationByUid(String orgId,
                                      ResultsHandler resultsHandler, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        Organization org = client.getOrganizationByUid(orgId);

        resultsHandler.handle(toConnectorObject(org, attributesToGet, allowPartialAttributeValues));
    }

    private ConnectorObject toConnectorObject(Organization org, Set<String> attributesToGet, boolean allowPartialAttributeValues) throws Auth0Exception {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(ORGANIZATION_OBJECT_CLASS)
                .setUid(org.getId())
                .setName(org.getName());

        if (shouldReturn(attributesToGet, ATTR_DISPLAY_NAME)) {
            if (org.getDisplayName() != null) {
                builder.addAttribute(ATTR_DISPLAY_NAME, org.getDisplayName());
            }
        }

        Branding branding = org.getBranding();
        if (branding != null) {
            if (shouldReturn(attributesToGet, ATTR_BRANDING_LOG_URL)) {
                if (branding.getLogoUrl() != null) {
                    builder.addAttribute(ATTR_BRANDING_LOG_URL, branding.getLogoUrl());
                }
            }

            Colors colors = branding.getColors();
            if (colors != null) {
                if (shouldReturn(attributesToGet, ATTR_BRANDING_COLORS_PRIMARY)) {
                    if (colors.getPrimary() != null) {
                        builder.addAttribute(ATTR_BRANDING_COLORS_PRIMARY, colors.getPrimary());
                    }
                }
                if (shouldReturn(attributesToGet, ATTR_BRANDING_COLORS_PAGE_BACKGROUND)) {
                    if (colors.getPageBackground() != null) {
                        builder.addAttribute(ATTR_BRANDING_COLORS_PAGE_BACKGROUND, colors.getPageBackground());
                    }
                }
            }
        }

        return builder.build();
    }
}
