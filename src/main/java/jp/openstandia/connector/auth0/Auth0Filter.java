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

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;

import java.util.HashMap;
import java.util.Map;

/**
 * Spec for Amazon Cognito filter
 * https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-manage-user-accounts.html#cognito-user-pools-searching-for-users-using-listusers-api
 */
public class Auth0Filter {
    final String attributeName;
    final FilterType filterType;
    final String attributeValue;

    public Auth0Filter(String attributeName, FilterType filterType, String attributeValue) {
        this.attributeName = attributeName;
        this.filterType = filterType;
        this.attributeValue = attributeValue;
    }

    public Auth0Filter(String attributeName, FilterType filterType) {
        this.attributeName = attributeName;
        this.filterType = filterType;
        this.attributeValue = null;
    }

    public boolean isByName() {
        return attributeName.equals(Name.NAME) && filterType == FilterType.EXACT_MATCH;
    }

    public boolean isByUid() {
        return attributeName.equals(Uid.NAME) && filterType == FilterType.EXACT_MATCH;
    }

    public enum FilterType {
        EXACT_MATCH("="),
        PREFIX_MATCH("^=");

        private String type;

        FilterType(String type) {
            this.type = type;
        }

        String getType() {
            return this.type;
        }
    }

    public String toFilterString(Map<String, AttributeInfo> schema) {
        return toFilterString(schema, attributeValue);
    }

    public String toFilterString(Map<String, AttributeInfo> schema, String value) {
        if (!schema.containsKey(attributeName)) {
            throw new InvalidAttributeValueException("Invalid filter name: " + attributeName);
        }
        if (value == null) {
            throw new InvalidAttributeValueException("Invalid filter value: null");
        }

        StringBuilder sb = new StringBuilder();
        sb.append(schema.get(attributeName).getName());
        sb.append(" ");
        sb.append(filterType.getType());
        sb.append(" ");
        sb.append("\"");
        sb.append(escape(value));
        sb.append("\"");

        return sb.toString();
    }

    private String escape(String s) {
        return s.replaceAll("\"", "\\\"");
    }

    @Override
    public String toString() {
        return "CognitoUserPoolFilter{" +
                "attributeName='" + attributeName + '\'' +
                ", filterType=" + filterType +
                ", attributeValue='" + attributeValue + '\'' +
                '}';
    }

    public static class SubFilter extends Auth0Filter {

        private static final Map<String, AttributeInfo> schema = new HashMap() {
            {
                this.put("sub", AttributeInfoBuilder.define("sub"));
            }
        };

        public SubFilter() {
            super("sub", FilterType.EXACT_MATCH);
        }

        public String toFilterString(String uid) {
            return super.toFilterString(schema, uid);
        }
    }
}
