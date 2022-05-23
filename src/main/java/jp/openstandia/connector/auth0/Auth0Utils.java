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

import com.auth0.json.mgmt.Permission;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides utility methods
 *
 * @author Hiroyuki Wada
 */
public class Auth0Utils {

    public static ZonedDateTime toZoneDateTime(Date date) {
        ZoneId zone = ZoneId.systemDefault();
        return ZonedDateTime.ofInstant(date.toInstant(), zone);
    }

    public static ZonedDateTime toZoneDateTime(String yyyymmdd) {
        LocalDate date = LocalDate.parse(yyyymmdd);
        return date.atStartOfDay(ZoneId.systemDefault());
    }

    /**
     * Transform Auth0 Permission objects to permission text lists.
     * The permission text format is "{resourceServerId}#{resourceName}".
     *
     * @param permissions
     * @return
     */
    public static List<String> toTextPermissions(List<Permission> permissions) {
        return permissions.stream()
                .map(p -> p.getResourceServerId() + "#" + p.getName())
                .collect(Collectors.toList());
    }

    public static List<String> toTextOrgRoles(Map<String, List<String>> orgRoles) {
        List<String> textOrgRoles = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : orgRoles.entrySet()) {
            for (String roleId : entry.getValue()) {
                textOrgRoles.add(entry.getKey() + ":" + roleId);
            }
        }
        return textOrgRoles;
    }

    /**
     * Check if ALLOW_PARTIAL_ATTRIBUTE_VALUES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldAllowPartialAttributeValues(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getAllowPartialAttributeValues());
    }

    /**
     * Check if RETURN_DEFAULT_ATTRIBUTES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldReturnDefaultAttributes(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getReturnDefaultAttributes());
    }

    public static boolean shouldReturn(Set<String> attrsToGetSet, String attr) {
        if (attrsToGetSet == null) {
            return true;
        }
        return attrsToGetSet.contains(attr);
    }

    public static Attribute createIncompleteAttribute(String attr) {
        AttributeBuilder builder = new AttributeBuilder();
        builder.setName(attr).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
        builder.addValue(Collections.EMPTY_LIST);
        return builder.build();
    }

    public static void throwInvalidSchema(String name) throws InvalidAttributeValueException {
        InvalidAttributeValueException exception = new InvalidAttributeValueException(
                String.format("Auth0 doesn't support to set '%s' attribute", name));
        exception.setAffectedAttributeNames(Arrays.asList(name));
        throw exception;
    }

    /**
     * Create full set of ATTRIBUTES_TO_GET which is composed by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET.
     *
     * @param schema
     * @param options
     * @return
     */
    public static Set<String> createFullAttributesToGet(Map<String, AttributeInfo> schema, OperationOptions options) {
        Set<String> attributesToGet = null;
        if (shouldReturnDefaultAttributes(options)) {
            attributesToGet = new HashSet<>();
            attributesToGet.addAll(toReturnedByDefaultAttributesSet(schema));
        }
        if (options.getAttributesToGet() != null) {
            if (attributesToGet == null) {
                attributesToGet = new HashSet<>();
            }
            for (String a : options.getAttributesToGet()) {
                attributesToGet.add(a);
            }
        }
        return attributesToGet;
    }

    private static Set<String> toReturnedByDefaultAttributesSet(Map<String, AttributeInfo> schema) {
        return schema.entrySet().stream()
                .filter(entry -> entry.getValue().isReturnedByDefault())
                .map(entry -> entry.getKey())
                .collect(Collectors.toSet());
    }

    public static int resolvePageSize(Auth0Configuration configuration, OperationOptions options) {
        if (options.getPageSize() != null) {
            return options.getPageSize();
        }
        return configuration.getDefaultQueryPageSize();
    }

    public static int resolvePageOffset(OperationOptions options) {
        if (options.getPagedResultsOffset() != null) {
            return options.getPagedResultsOffset();
        }
        return 0;
    }
}