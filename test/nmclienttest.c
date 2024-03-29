#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>


char * get_active_device (DBusConnection *connection)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;
	char			*device_path;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						"/org/freedesktop/NetworkManager",
						"org.freedesktop.NetworkManager",
						"getActiveDevice");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	char *string;
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManager returned a NULL active device object path" );
		return;
	}

	fprintf (stderr, "Active device: '%s'\n", string );

	dbus_message_unref (reply);
	dbus_message_unref (message);

	device_path = g_strdup (string);
	return (device_path);
}


void get_device_name (DBusConnection *connection, char *path)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						path,
						"org.freedesktop.NetworkManager",
						"getName");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	char *string;
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManager returned a NULL active device object path" );
		return;
	}

	fprintf (stderr, "Active device name: '%s'\n", string );

	dbus_message_unref (reply);
	dbus_message_unref (message);
}

void get_device_active_network (DBusConnection *connection, char *path)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						path,
						"org.freedesktop.NetworkManager",
						"getActiveNetwork");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	char *string;
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManager returned a NULL active device object path" );
		return;
	}

	fprintf (stderr, "Active device's Network: '%s' ", string );

	dbus_message_unref (reply);
	dbus_message_unref (message);

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						string,
						"org.freedesktop.NetworkManager",
						"getName");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	string = dbus_message_iter_get_string (&iter);
	if (!string)
	{
		fprintf (stderr, "NetworkManager returned a NULL active device object path" );
		return;
	}

	fprintf (stderr, " (%s)\n", string );

	dbus_message_unref (reply);
	dbus_message_unref (message);
}


int get_device_type (DBusConnection *connection, char *path)
{
	DBusMessage	*message;
	DBusMessage	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						path,
						"org.freedesktop.NetworkManager",
						"getType");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return (-1);
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return (-1);
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return (-1);
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	int	type;
	type = dbus_message_iter_get_int32 (&iter);

	fprintf (stderr, "Active device type: '%d'\n", type );

	dbus_message_unref (reply);
	dbus_message_unref (message);

	return (type);
}


void get_device_networks (DBusConnection *connection, const char *path)
{
	DBusMessage 	*message;
	DBusMessage 	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						path,
						"org.freedesktop.NetworkManager",
						"getNetworks");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	char **networks;
	int	num_networks;

	if (!dbus_message_iter_get_string_array (&iter, &networks, &num_networks))
	{
		fprintf (stderr, "NetworkManager returned no device list" );
		return;
	}

	dbus_message_unref (reply);
	dbus_message_unref (message);

	int i;
	fprintf( stderr, "Networks:\n" );
	for (i = 0; i < num_networks; i++)
	{
		DBusMessage	*message2;
		DBusMessage	*reply2;
		DBusMessageIter iter2;
		DBusError		 error2;

		message2 = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
							networks[i],
							"org.freedesktop.NetworkManager",
							"getName");
		if (message2 == NULL)
		{
			fprintf (stderr, "Couldn't allocate the dbus message\n");
			return;
		}

		dbus_error_init (&error2);
		reply2 = dbus_connection_send_with_reply_and_block (connection, message2, -1, &error2);
		if (dbus_error_is_set (&error2))
		{
			fprintf (stderr, "%s raised:\n %s\n\n", error2.name, error2.message);
			dbus_message_unref (message2);
			return;
		}
	
		if (reply2 == NULL)
		{
			fprintf( stderr, "dbus reply message was NULL\n" );
			dbus_message_unref (message2);
			return;
		}
	
		/* now analyze reply */
		dbus_message_iter_init (reply2, &iter2);
		const char *string2 = dbus_message_iter_get_string (&iter2);
		if (!string2)
		{
			fprintf (stderr, "NetworkManager returned a NULL active device object path" );
			return;
		}
	
		dbus_message_unref (reply2);
		dbus_message_unref (message2);

		fprintf( stderr, "   %s (%s)\n", networks[i], string2 );
	}

	dbus_free_string_array (networks);
}


void get_devices (DBusConnection *connection)
{
	DBusMessage 	*message;
	DBusMessage 	*reply;
	DBusMessageIter iter;
	DBusError		 error;

	message = dbus_message_new_method_call ("org.freedesktop.NetworkManager",
						"/org/freedesktop/NetworkManager",
						"org.freedesktop.NetworkManager",
						"getDevices");
	if (message == NULL)
	{
		fprintf (stderr, "Couldn't allocate the dbus message\n");
		return;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s raised:\n %s\n\n", error.name, error.message);
		dbus_message_unref (message);
		return;
	}

	if (reply == NULL)
	{
		fprintf( stderr, "dbus reply message was NULL\n" );
		dbus_message_unref (message);
		return;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &iter);
	char **devices;
	int	num_devices;

	if (!dbus_message_iter_get_string_array (&iter, &devices, &num_devices))
	{
		fprintf (stderr, "NetworkManager returned no device list" );
		return;
	}

	dbus_message_unref (reply);
	dbus_message_unref (message);

	int i;
	fprintf( stderr, "Devices:\n" );
	for (i = 0; i < num_devices; i++)
		fprintf( stderr, "   %s\n", devices[i] );

	dbus_free_string_array (devices);
}


int main( int argc, char *argv[] )
{
	DBusConnection *connection;
	DBusError		error;

	g_type_init ();

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL)
	{
		fprintf (stderr, "Error connecting to system bus: %s\n", error.message);
		dbus_error_free (&error);
		return 1;
	}

	char *path;
	int	 type;

	path = get_active_device (connection);
	get_device_name (connection, path);
	type = get_device_type (connection, path);
	if (type == 2)
	{
		get_device_active_network (connection, path);
		get_device_networks (connection, path);
	}

	get_devices (connection);
	g_free (path);

	return 0;
}
