//  Copyright 2020 Security Onion Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
// 
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

package com.securityonionsolutions.elastic.ingestcommunityid;

import com.rapid7.communityid.CommunityIdGenerator;
import com.rapid7.communityid.Protocol;
import org.elasticsearch.ingest.AbstractProcessor;
import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.ingest.Processor;

import java.net.InetAddress;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Locale;

import static org.elasticsearch.ingest.ConfigurationUtils.readStringProperty;
import static org.elasticsearch.ingest.ConfigurationUtils.readObject;

public class CommunityIdProcessor extends AbstractProcessor {

    public static final String TYPE = "community_id";

    private final List<String> fields;
    private final String targetField;

    public CommunityIdProcessor(String tag, String description, List<String> field, String targetField) throws IOException {
        super(tag, description);
        this.fields = new ArrayList<>(field);
        this.targetField = targetField;
    }

    @Override
    public IngestDocument execute(IngestDocument document) throws Exception {
        CommunityIdGenerator generator = new CommunityIdGenerator();

        if (document.hasField(fields.get(0), true) == false ||
            document.hasField(fields.get(1), true) == false ||
            document.hasField(fields.get(2), true) == false ||
            document.hasField(fields.get(3), true) == false ||
            document.hasField(fields.get(4), true) == false
        ) {
            return document;
        }

        String sourceIp = document.getFieldValue(fields.get(0), String.class);
        Integer sourcePort = getPort(fields.get(1), document);
        String destinationIp = document.getFieldValue(fields.get(2), String.class);
        Integer destinationPort = getPort(fields.get(3), document);
        String protocol = document.getFieldValue(fields.get(4), String.class);

        String result = generator.generateCommunityId(getProtocol(protocol),
                InetAddress.getByName(sourceIp), sourcePort,
                InetAddress.getByName(destinationIp), destinationPort);
        document.setFieldValue(targetField, result);
        return document;
    }

    private Protocol getProtocol(String protocol) {
        if (protocol.toLowerCase(Locale.ROOT).equals("tcp"))
            return Protocol.TCP;
        else if (protocol.toLowerCase(Locale.ROOT).equals("udp"))
            return Protocol.UDP;
        else if (protocol.toLowerCase(Locale.ROOT).equals("sctp"))
            return Protocol.SCTP;
        else
            return Protocol.TCP;
    }

    private Integer getPort(String portField, IngestDocument document) {
        Integer port;
        try {
            port = document.getFieldValue(portField, Integer.class);
        } catch (Exception e) {
            String temp = document.getFieldValue(portField, String.class);
            port = Integer.parseInt(temp);
        }
        return port;
    }

    @Override
    public String getType() {
        return TYPE;
    }

    public static final class Factory implements Processor.Factory {
        @Override
        public CommunityIdProcessor create(Map<String, Processor.Factory> factories, String tag, String description, Map<String, Object> config)
                throws Exception {
            final List<String> fields = new ArrayList<>();
            final Object field = readObject(TYPE, tag, config, "field");

            if (field instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> stringList = (List<String>) field;
                fields.addAll(stringList);
            } else {
                throw new IllegalArgumentException("field should be an Array");
            }

            String targetField = readStringProperty(TYPE, tag, config, "target_field", "default_field_name");

            return new CommunityIdProcessor(tag, description, fields, targetField);
        }
    }
}