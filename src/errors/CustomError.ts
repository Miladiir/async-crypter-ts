/**
 * Error whose name relects the Error class name.
 */
export class CustomError extends Error {

    /**
     * Instantiate a new error object.
     * @param message The error message.
     */
    public constructor(message?: string) {

        super(message);
        this.name = new.target.name;
    }
}