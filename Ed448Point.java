/*
 * David Hoang, Faith Capito
 *
 * TCSS487 - Spring 2024
 */

import java.math.BigInteger;

/***
 * Object representing a curve point on an Edwards curve.
 * This class represents points on the Ed448-Goldilocks elliptic curve.
 * The Ed448-Goldilocks curve is an Edwards curve defined by the equation:
 * x^2 + y^2 = 1 + dx^2y^2 with d = -39081 and the prime modulus p = 2^448 - 2^224 - 1.
 *
 */
public class Ed448Point {

    // Prime modulus for the finite field Fp
    public static final BigInteger P = (BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE));
    // Curve parameter D
    public static final BigInteger D = BigInteger.valueOf(-39081);

    public static final Ed448Point G = new Ed448Point(false, BigInteger.valueOf(8), P);

    private BigInteger x;
    private BigInteger y;

    /**
     * Default constructor for the neutral element (0, 1).
     */
    public Ed448Point() {
        this(BigInteger.ZERO, BigInteger.ONE);
    }

    /**
     * Constructor for a point with specified x and y coordinates.
     *
     * @param x The x-coordinate.
     * @param y The y-coordinate.
     */
    public Ed448Point(BigInteger x, BigInteger y) {
        this.x = x.mod(P);
        this.y = y.mod(P);
        if (!isValidPoint()) {
            throw new IllegalArgumentException("The provided coordinates do not lie on the curve");
        }
    }

    /**
     * Constructor to create an Edwards point given the y-coordinate and
     * a specified least significant bit for the x-coordinate.
     *
     * @param xLsb The least significant bit of the x-coordinate.
     * @param y The y-coordinate of the point.
     */
    public Ed448Point(boolean xLsb, BigInteger x, BigInteger y) {
        this.x = x;
        BigInteger numerator = BigInteger.ONE.subtract(x.pow(2));
        BigInteger denominator = BigInteger.ONE.subtract(D.multiply(x.pow(2))); // 1 + 39801 * x^2, d = -39801
        BigInteger v = numerator.multiply(denominator.modInverse(P)).mod(P);
        this.y = sqrt(v, P, xLsb);
    }

    public BigInteger getX() {
        return this.x;
    }


    public BigInteger getY() {
        return this.y;
    }

    /**
     * Add this point to another point using the Edwards point addition formula.
     *
     * @param pt The other point.
     * @return The sum of the points.
     */

    public Ed448Point add(Ed448Point pt) {
        BigInteger factor = this.x.multiply(this.y).multiply(pt.x).multiply(pt.y);
        BigInteger nX = (this.x.multiply(pt.y)).add(this.y.multiply(pt.x));
        BigInteger dX = BigInteger.ONE.add(D.multiply(factor));
        BigInteger nY = (this.y.multiply(pt.y)).subtract(this.x.multiply(pt.x));
        BigInteger dY = BigInteger.ONE.subtract(D.multiply(factor));

        BigInteger xCoor = (nX.multiply(dX.modInverse(P))).mod(P);
        BigInteger yCoor = (nY.multiply(dY.modInverse(P))).mod(P);

        return new Ed448Point(xCoor, yCoor);
    }

    /**
     * Multiply a scalar on this point using the double-and-add method.
     *
     * @param k  The scalar to multiply with.
     * @return The product of multiplying this Edwards point by the scalar.
     */
    public Ed448Point multiply(BigInteger k) {

        if (k.signum() < 0) {
            return this.negate().multiply(k.negate());
        }
        Ed448Point result = new Ed448Point(); // Start with the neutral element (0, 1)
        Ed448Point addend = this;

        for (int i = k.bitLength() - 1; i >= 0; i--) {
            result = result.add(result); // Double the point
            if (k.testBit(i)) {
                result = result.add(addend); // Add the base point if the bit is set
            }
        }

        return result;
    }


    public Ed448Point negate() {
        return new Ed448Point(x.negate().mod(P), y);
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v The radicand.
     * @param p The modulus (must satisfy p mod 4 = 3).
     * @param lsb Desired least significant bit (true: 1, false: 0).
     * @return A square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    private BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Check if the point is valid, i.e., it satisfies the curve equation.
     *
     * @return True if the point is valid, false otherwise.
     */
    private boolean isValidPoint() {
        BigInteger x2 = x.multiply(x).mod(P);
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger left = x2.add(y2).mod(P);
        BigInteger right = BigInteger.ONE.add(D.multiply(x2).multiply(y2)).mod(P);
        return left.equals(right);
    }

    /**
     * Converts the point to a string representation.
     *
     * @return The string representation of the point.
     */
    @Override
    public String toString() {
        return "X is: " + x.toString(10) + " and Y is " + y.toString(10);
    }

    /**
     * Main method for testing the Ed448Point class.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) {
        // Example usage of Ed448Point class
//
//        Ed448Point G = new Ed448Point(new BigInteger("123456789"), new BigInteger("987654321"));
//        BigInteger scalar = new BigInteger("123456789"); // Example scalar
//        Ed448Point result = G.multiply(scalar, D, P);
//        System.out.println("Result of multiplication: " + result);

        //Example 2:

//        BigInteger yCoordinate = new BigInteger("987654321");
//        boolean xLsb = true; // Set the least significant bit of x-coordinate to 1
//        BigInteger curveParameterD = new BigInteger("-39081");
//        BigInteger primeModulusP = BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);
//
//        // Create an Ed448Point with specified least significant bit for x-coordinate
//        Ed448Point point = new Ed448Point(xLsb, yCoordinate, curveParameterD, primeModulusP);
//
//        // Print the created point
//        System.out.println("Created point with specified least significant bit for x-coordinate: " + point);
    }


}
