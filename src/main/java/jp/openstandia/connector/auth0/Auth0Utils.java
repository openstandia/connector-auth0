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

import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderResponse;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Provides utility methods
 *
 * @author Hiroyuki Wada
 */
public class Auth0Utils {

    public static ZonedDateTime toZoneDateTime(Instant instant) {
        ZoneId zone = ZoneId.systemDefault();
        return ZonedDateTime.ofInstant(instant, zone);
    }

    public static ZonedDateTime toZoneDateTime(String yyyymmdd) {
        LocalDate date = LocalDate.parse(yyyymmdd);
        return date.atStartOfDay(ZoneId.systemDefault());
    }

    /**
     * Transform a Cognito attribute object to a Connector attribute object.
     *
     * @param attributeInfo
     * @param a
     * @return
     */
    public static Attribute toConnectorAttribute(AttributeInfo attributeInfo, AttributeType a) {
        // Cognito API returns the attribute as string even if it's other types.
        // We need to check the type from the schema and convert it.
        // Also, we must escape the name for custom attributes (The name of custom attribute starts with "custom:").
        if (attributeInfo.getType() == Integer.class) {
            return AttributeBuilder.build(a.name(), Integer.parseInt(a.value()));
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format is YYYY-MM-DD
            return AttributeBuilder.build(a.name(), toZoneDateTime(a.value()));
        }
        if (attributeInfo.getType() == Boolean.class) {
            return AttributeBuilder.build(a.name(), Boolean.parseBoolean(a.value()));
        }

        // String
        return AttributeBuilder.build(a.name(), a.value());
    }

    public static AttributeType toCognitoAttribute(Map<String, AttributeInfo> schema, AttributeDelta delta) {
        return AttributeType.builder()
                .name(delta.getName())
                .value(toCognitoValue(schema, delta))
                .build();
    }

    /**
     * Transform a Connector attribute object to a Cognito attribute object.
     *
     * @param schema
     * @param attr
     * @return
     */
    public static AttributeType toCognitoAttribute(Map<String, AttributeInfo> schema, Attribute attr) {
        return AttributeType.builder()
                .name(attr.getName())
                .value(toCognitoValue(schema, attr))
                .build();
    }

    private static String toCognitoValue(Map<String, AttributeInfo> schema, AttributeDelta delta) {
        // The key of the schema is escaped key
        AttributeInfo attributeInfo = schema.get(delta.getName());
        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + delta.getName());
        }

        if (attributeInfo.getType() == Integer.class) {
            return AttributeDeltaUtil.getAsStringValue(delta);
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format must be YYYY-MM-DD in cognito
            ZonedDateTime date = (ZonedDateTime) AttributeDeltaUtil.getSingleValue(delta);
            return date.format(DateTimeFormatter.ISO_LOCAL_DATE);
        }
        if (attributeInfo.getType() == Boolean.class) {
            return AttributeDeltaUtil.getAsStringValue(delta);
        }

        return AttributeDeltaUtil.getAsStringValue(delta);
    }

    private static String toCognitoValue(Map<String, AttributeInfo> schema, Attribute attr) {
        // The key of the schema is escaped key
        AttributeInfo attributeInfo = schema.get(attr.getName());
        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + attr.getName());
        }

        if (attributeInfo.getType() == Integer.class) {
            return AttributeUtil.getAsStringValue(attr);
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format must be YYYY-MM-DD in cognito
            ZonedDateTime date = (ZonedDateTime) AttributeUtil.getSingleValue(attr);
            return date.format(DateTimeFormatter.ISO_LOCAL_DATE);
        }
        if (attributeInfo.getType() == Boolean.class) {
            return AttributeUtil.getAsStringValue(attr);
        }

        return AttributeUtil.getAsStringValue(attr);
    }

    public static AttributeType toCognitoAttributeForDelete(AttributeDelta delta) {
        // Cognito deletes the attribute when updating the value with ""
        return AttributeType.builder()
                .name(delta.getName())
                .value("")
                .build();
    }

    /**
     * Transform a Connector attribute object to a Cognito attribute object for deleting the value.
     *
     * @param attr
     * @return
     */
    public static AttributeType toCognitoAttributeForDelete(Attribute attr) {
        // Cognito deletes the attribute when updating the value with ""
        return AttributeType.builder()
                .name(attr.getName())
                .value("")
                .build();
    }

    /**
     * Check cognito result if it returns unexpected error.
     *
     * @param result
     * @param apiName
     */
    public static void checkCognitoResult(CognitoIdentityProviderResponse result, String apiName) {
        int status = result.sdkHttpResponse().statusCode();
        if (status != 200) {
            throw new ConnectorException(String.format("Cognito returns unexpected error when calling \"%s\". status: %d", apiName, status));
        }
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

    public static void invalidSchema(String name) throws InvalidAttributeValueException {
        InvalidAttributeValueException exception = new InvalidAttributeValueException(
                String.format("Cognito doesn't support to set '%s' attribute", name));
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
}
