//
//  File.swift
//  
//
//  Created by Iain McLaren on 25/3/2024.
//

import Foundation

struct TypeIDAndData: Codable {
    let type: String
    let id:   String
    let data: String
    
    public enum CodingKeys: String, CodingKey {
        case type = "Type"
        case id   = "ID"
        case data = "Data"
    }
    
    public init(type: String, id: String, data: String) {
        self.type = type
        self.id   = id
        self.data = data
    }
}
