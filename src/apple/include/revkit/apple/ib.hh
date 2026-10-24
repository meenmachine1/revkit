// Interface Builder's compiled files and NSKeyedArchiver archives
// (docs/apple-apps.md, "Interface Builder"), read as data, never
// instantiated:
//
//   parse_nib_archive()      iOS's compiled nibs (NIBArchive): objects of
//                            classes with keyed values
//   KeyedArchive             an NSKeyedArchiver plist's $objects, $top and
//                            UID references, resolved on demand; resolve()
//                            makes a tree of it (each object expanded
//                            once, later references and cycles as $ref)
//   read_interface_builder() either kind of nib as one object graph: its
//                            objects (classes, custom classes, File's
//                            Owner and First Responder placeholders, view
//                            parents, labels) and its outlet and action
//                            connections (source, destination, selector or
//                            outlet name, UIKit's control events)
//
// Bounded for hostile input as plist.hh's readers are.
#pragma once

#include "revkit/apple/plist.hh"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::apple {

// ---- NIBArchive -------------------------------------------------------------

struct NibValue {
  enum class Type : std::uint8_t { integer, real, boolean, nil, data, ref };
  Type type = Type::nil;
  std::int64_t integer = 0;
  double real = 0;
  bool boolean = false;
  std::string data;
  std::uint32_t ref = 0;  // an object's index
};

struct NibObject {
  std::string class_name;  // trailing NULs dropped
  std::vector<std::pair<std::string, NibValue>> values;  // in archive order; keys repeat (arrays)
  const NibValue *get(std::string_view key) const;
};

struct NibArchive {
  std::uint32_t format_version = 0;
  std::uint32_t coder_version = 0;
  std::vector<NibObject> objects;
};

bool is_nib_archive(std::span<const std::byte> head);
NibArchive parse_nib_archive(std::span<const std::byte> bytes, const Limits &limits = {});

// ---- NSKeyedArchiver -----------------------------------------------------------

class KeyedArchive {
 public:
  // Error when the plist isn't an NSKeyedArchiver archive ($archiver,
  // $objects, $top).
  explicit KeyedArchive(const Value &plist);
  static bool is_keyed_archive(const Value &plist);

  std::size_t size() const { return objects_->size(); }
  // $top's UID for `key` ("root", "IB.objectdata").
  std::optional<std::uint64_t> top(std::string_view key) const;
  const Value &top_dict() const { return *top_; }
  // The object a UID names; null past $objects (UID 0 is "$null").
  const Value *object(std::uint64_t uid) const;
  // Its class name ($class's $classname), "" when it has none.
  std::string class_name(std::uint64_t uid) const;
  // A field of an object: its raw value, a UID it holds, the string it
  // names (a string object, or an NSString's NS.string or NS.bytes), the
  // UIDs of an NSArray or NSSet it names (NS.objects).
  const Value *field(std::uint64_t uid, std::string_view key) const;
  std::optional<std::uint64_t> ref(std::uint64_t uid, std::string_view key) const;
  std::optional<std::string> string(std::uint64_t uid, std::string_view key) const;
  std::optional<std::string> string_of(std::uint64_t uid) const;
  std::vector<std::uint64_t> array(std::uint64_t uid, std::string_view key) const;
  std::vector<std::uint64_t> array_of(std::uint64_t uid) const;

  // The archive as a tree: {"$top": {key: object}}, each object a
  // dictionary with "$class" (its class name) and its fields, arrays
  // (NS.objects) as arrays, NSDictionary (NS.keys, NS.objects) as a
  // dictionary, strings and numbers as themselves. An object is expanded
  // where it is first reached; later references (and cycles) are
  // {"$ref": uid, "$class": name}. At most `max_values` values.
  Value resolve(std::uint64_t max_values = 200000) const;

 private:
  const Value *top_ = nullptr;
  const std::vector<Value> *objects_ = nullptr;
};

// ---- Interface Builder documents -------------------------------------------------

struct IbObject {
  std::uint32_t id = 0;     // the archive's object index (NIBArchive) or UID
  std::string class_name;   // as archived: "UIButton", "UIClassSwapper", "NSCustomObject"
  // The class it is at run time: a class swapper's or custom object's
  // class (UIClassName, NSClassName), else class_name.
  std::string custom_class;
  std::string original_class;  // a class swapper's UIOriginalClassName / NSOriginalClassName
  // "files-owner", "first-responder", "application" (placeholders), "".
  std::string placeholder;
  std::string label;  // a title, text or accessibility label it carries
  std::optional<std::uint32_t> parent;  // its superview, or its parent in the nib
  std::string nib_name;               // a storyboard controller's UINibName (its view's nib)
  std::string storyboard_identifier;  // UIStoryboardIdentifier
};

struct IbConnection {
  enum class Kind : std::uint8_t { outlet, action };
  Kind kind = Kind::action;
  std::uint32_t id = 0;
  std::string label;  // the outlet's name, or the action's selector
  std::optional<std::uint32_t> source;       // the control (actions), the owner (outlets)
  std::optional<std::uint32_t> destination;  // the target (nil: the first responder) or the outlet's object
  std::uint64_t event_mask = 0;              // UIKit's UIControlEvents (actions); 0 on macOS
  std::vector<std::string> events;           // its names: "touchUpInside", "valueChanged", ...
};

struct IbDocument {
  std::string format;  // "nib:archive", "nib:keyed"
  std::vector<IbObject> objects;
  std::vector<IbConnection> connections;
  std::vector<std::string> warnings;
  const IbObject *object(std::uint32_t id) const;
};

// A compiled nib's bytes (a NIBArchive, or a keyed archive plist). Error
// when it is neither.
IbDocument read_interface_builder(std::span<const std::byte> bytes, const Limits &limits = {});

// UIControlEvents' names for a mask (UIKit's enum: "touchDown", ...,
// "editingDidEndOnExit"); unknown bits as hex.
std::vector<std::string> control_event_names(std::uint64_t mask);

}  // namespace revkit::apple
