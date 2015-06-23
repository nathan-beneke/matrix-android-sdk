/* 
 * Copyright 2014 OpenMarket Ltd
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
package org.matrix.androidsdk.rest.model.bingrules;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.annotations.SerializedName;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class BingRule {

    public static String RULE_ID_DISABLE_ALL = ".m.rule.master";
    public static String RULE_ID_CONTAIN_USER_NAME= ".m.rule.contains_user_name";
    public static String RULE_ID_CONTAIN_DISPLAY_NAME= ".m.rule.contains_display_name";
    public static String RULE_ID_ONE_TO_ONE_ROOM = ".m.rule.room_one_to_one";
    public static String RULE_ID_INVITE_ME = ".m.rule.invite_for_me";
    public static String RULE_ID_PEOPLE_JOIN_LEAVE = ".m.rule.member_event";
    public static String RULE_ID_CALL = ".m.rule.call";
    public static String RULE_ID_SUPPRESS_BOTS_NOTIFICATIONS = ".m.rule.suppress_notices";
    public static String RULE_ID_ALL_OTHER_MESSAGES_ROOMS = ".m.rule.message";

    public static final String ACTION_NOTIFY = "notify";
    public static final String ACTION_DONT_NOTIFY = "dont_notify";
    public static final String ACTION_COALESCE = "coalesce";

    public static final String ACTION_SET_TWEAK_SOUND_VALUE = "sound";
    public static final String ACTION_SET_TWEAK_HIGHTLIGHT_VALUE = "highlight";

    public static final String ACTION_PARAMETER_SET_TWEAK = "set_tweak";
    public static final String ACTION_PARAMETER_VALUE = "value";

    public static final String ACTION_VALUE_DEFAULT = "default";
    public static final String ACTION_VALUE_TRUE = "true";
    public static final String ACTION_VALUE_FALSE = "false";

    public String ruleId = null;
    public List<Condition> conditions = null;
    public List<JsonElement> actions = null;
    @SerializedName("default")
    public boolean isDefault = false;

    @SerializedName("enabled")
    public boolean isEnabled = true;

    public BingRule(boolean isDefaultValue) {
        this.isDefault = isDefaultValue;
    }

    public BingRule() {
        this.isDefault = false;
    }

    public BingRule deepCopy() {
        BingRule rule = new BingRule();
        rule.ruleId = ruleId;

        if (null != conditions) {
            ArrayList<Condition> conditionsCopy = new ArrayList<Condition>();

            for(Condition condition : conditions) {
                conditionsCopy.add(condition.deepCopy());
            }
            rule.conditions = conditionsCopy;
        }

        if (null != actions) {
            ArrayList<JsonElement> actionsCopy =  new ArrayList<JsonElement>();

            for(JsonElement element : actions) {
                actionsCopy.add(element);
            }
            rule.actions = actionsCopy;
        }

        rule.isDefault = isDefault;
        rule.isEnabled = isEnabled;

        return rule;
    }

    public void addCondition(Condition condition) {
        if (conditions == null) {
            conditions = new ArrayList<Condition>();
        }
        conditions.add(condition);
    }

    /**
     * Search a JsonElement from its tweak name
     * @param tweak the tweak name.
     * @return the json element. null if not found.
     */
    private JsonObject jsonObjectWithTweak(String tweak) {
        JsonObject jsonObject = null;

        if (null != actions) {
            for (JsonElement json : actions) {
                if (json.isJsonObject()) {
                    JsonObject object = json.getAsJsonObject();
                    try {
                        if (object.has(ACTION_PARAMETER_SET_TWEAK)) {
                            if (object.get(ACTION_PARAMETER_SET_TWEAK).getAsString().equals(tweak)) {
                                jsonObject = object;
                                break;
                            }
                        }
                    } catch (Exception e) {

                    }
                }
            }
        }

        return jsonObject;
    }

    /**
     * Search a JsonPrimitive from its value.
     * @param value the jsonPrimitive value.
     * @return the json primitive. null if not found.
     */
    private JsonPrimitive jsonPrimitive(String value) {
        JsonPrimitive jsonPrimitive = null;

        if (null != actions) {
            for (JsonElement json : actions) {
                if (json.isJsonPrimitive()) {
                    JsonPrimitive primitive = json.getAsJsonPrimitive();

                    try {
                        if (primitive.getAsString().equals(value)) {
                            jsonPrimitive = primitive;
                            break;
                        }
                    } catch (Exception e) {

                    }
                }
            }
        }
        return jsonPrimitive;
    }

    /**
     * Return true if the rule should play sound .
     * @return true if the rule should play sound
     */
    public boolean shouldPlaySound() {
        boolean playSound = false;
        JsonObject jsonObject = jsonObjectWithTweak(ACTION_SET_TWEAK_SOUND_VALUE);

        if ((null != jsonObject) && jsonObject.has(ACTION_PARAMETER_VALUE)) {
            playSound = jsonObject.get(ACTION_PARAMETER_VALUE).getAsString().equals(ACTION_VALUE_DEFAULT);
        }

        return playSound;
    }

    /**
     * Return true if the rule should highlight the event.
     * @return true if the rule should play sound
     */
    public boolean shouldHighlight() {
        boolean highlight = false;
        JsonObject jsonObject = jsonObjectWithTweak(ACTION_SET_TWEAK_HIGHTLIGHT_VALUE);

        if ((null != jsonObject) && jsonObject.has(ACTION_PARAMETER_VALUE)) {
            highlight = jsonObject.get(ACTION_PARAMETER_VALUE).getAsString().equals(ACTION_VALUE_TRUE);
        }

        return highlight;
    }

    /**
     * Return true if the rule should highlight the event.
     * @return true if the rule should play sound
     */
    public boolean shouldNotify() {
        return null != jsonPrimitive(ACTION_NOTIFY);
    }
}