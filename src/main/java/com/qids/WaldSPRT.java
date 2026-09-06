package com.qids;

/**
 * Wald Sequential Probability Ratio Test (SPRT) Detector for Quantum Physical-Layer Monitoring.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class WaldSPRT {

    public enum State {
        CONTINUE,
        ACCEPT_H0,
        ACCEPT_H1
    }

    private final double p0;
    private final double p1;
    private final double alpha;
    private final double beta;

    private double llr;
    private int nSamples;
    private int nErrors;
    private State state;
    private int stoppedAt;

    private final double logErrRatio;
    private final double logOkRatio;
    private final double upperBound;
    private final double lowerBound;

    public WaldSPRT(double p0, double p1, double alpha, double beta) {
        if (!(0.0 <= p0 && p0 < p1 && p1 <= 1.0)) {
            throw new IllegalArgumentException("Requirement failed: 0.0 <= p0 < p1 <= 1.0");
        }
        if (!(0.0 < alpha && alpha < 1.0 && 0.0 < beta && beta < 1.0)) {
            throw new IllegalArgumentException("Requirement failed: alpha and beta must be in (0, 1)");
        }

        double q0 = Math.max(p0, 1e-6);
        double q1 = Math.min(p1, 1.0 - 1e-6);

        this.p0 = p0;
        this.p1 = p1;
        this.alpha = alpha;
        this.beta = beta;
        this.llr = 0.0;
        this.nSamples = 0;
        this.nErrors = 0;
        this.state = State.CONTINUE;
        this.stoppedAt = 0;

        this.logErrRatio = Math.log(q1 / q0);
        this.logOkRatio = Math.log((1.0 - q1) / (1.0 - q0));
        this.upperBound = Math.log((1.0 - beta) / alpha);
        this.lowerBound = Math.log(beta / (1.0 - alpha));
    }

    public synchronized State update(boolean isError) {
        if (state != State.CONTINUE) {
            return state;
        }

        nSamples++;
        if (isError) {
            nErrors++;
            llr += logErrRatio;
        } else {
            llr += logOkRatio;
        }

        if (llr >= upperBound) {
            state = State.ACCEPT_H1;
            stoppedAt = nSamples;
        } else if (llr <= lowerBound) {
            state = State.ACCEPT_H0;
            stoppedAt = nSamples;
        }

        return state;
    }

    public synchronized State feed(boolean[] errors) {
        for (boolean err : errors) {
            if (update(err) != State.CONTINUE) {
                break;
            }
        }
        return state;
    }

    public synchronized void reset() {
        this.llr = 0.0;
        this.nSamples = 0;
        this.nErrors = 0;
        this.state = State.CONTINUE;
        this.stoppedAt = 0;
    }

    public synchronized double getLLR() {
        return llr;
    }

    public synchronized State getState() {
        return state;
    }

    public synchronized int getSamples() {
        return nSamples;
    }

    public synchronized int getErrors() {
        return nErrors;
    }

    public synchronized int getStoppedAt() {
        return stoppedAt;
    }
}
