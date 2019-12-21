package uk.co.platosys.minigma.exceptions;

import android.util.Log;

public class Exceptions {
    public static void dump ( Throwable e) {
        //Log.e("DUMP", "error", e);  //comment out to get testing to run.
        System.out.println(e.getClass().getName() + ":" + e.getMessage());
        if (e.getCause() != null) {

            System.out.println("Cause:"+e.getCause().getClass().getName());
            dump(e.getCause());
        } else {
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement : stackTraceElements) {
                System.out.println(stackTraceElement.toString());
            }
        }
    }

    public static void dump (String TAG, Throwable e) {
        //Log.e("DUMP", "error", e);  //comment out to get testing to run.
        System.out.println(e.getClass().getName() + ":" + e.getMessage());
        if (e.getCause() != null) {
            dump(TAG, e.getCause());
        } else {
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement : stackTraceElements) {
                System.out.println(stackTraceElement.toString());
            }
        }
    }
    public static void dump (String TAG, String msg, Throwable e) {
        //Log.e("DUMP", "error", e);  //comment out to get testing to run.
        System.out.println(msg);
        System.out.println(e.getClass().getName() + ":" + e.getMessage());
        if (e.getCause() != null) {
            dump(TAG, e.getCause());
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