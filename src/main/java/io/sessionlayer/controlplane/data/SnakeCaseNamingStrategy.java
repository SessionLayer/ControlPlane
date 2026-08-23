package io.sessionlayer.controlplane.data;

import org.springframework.data.relational.core.mapping.NamingStrategy;
import org.springframework.data.relational.core.mapping.RelationalPersistentProperty;

public class SnakeCaseNamingStrategy implements NamingStrategy {

	@Override
	public String getColumnName(RelationalPersistentProperty property) {
		return camelToSnake(property.getName());
	}

	private static String camelToSnake(String name) {
		StringBuilder sb = new StringBuilder(name.length() + 8);
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (Character.isUpperCase(c)) {
				if (i > 0) {
					sb.append('_');
				}
				sb.append(Character.toLowerCase(c));
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}
}
