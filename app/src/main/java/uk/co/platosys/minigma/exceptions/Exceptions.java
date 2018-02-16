package uk.co.platosys.minigma.exceptions;

import android.util.Log;

public class Exceptions {

    public static void dump (Throwable e) {
        Log.e("DUMP", "error", e);
        System.out.println(e.getClass().getName() + ":" + e.getMessage());
        if (e.getCause() != null) {
            dump(e.getCause());
        } else {
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement : stackTraceElements) {
                System.out.println(stackTraceElement.toString());
            }
        }
    }
}

/*
switch




 */