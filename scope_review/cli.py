import argparse
import sys

from .core import Invalid, encode, load, review


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review agent tool permission changes offline.")
    parser.add_argument("before", help="Baseline policy JSON")
    parser.add_argument("after", help="Proposed policy JSON")
    parser.add_argument("--cases", required=True, help="Expected decisions for proposed policy")
    args = parser.parse_args(argv)
    try:
        result = review(load(args.before), load(args.after), load(args.cases))
        sys.stdout.buffer.write(encode(result))
        return 0 if result["gate"] == "pass" else 1
    except Invalid as error:
        print(encode({"error": str(error)}).decode(), end="", file=sys.stderr)
        return 2
    except OSError:
        print('{"error":"filesystem or output operation failed"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
