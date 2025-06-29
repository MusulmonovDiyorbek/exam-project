import { Model } from "src/model/entities/model.entity";
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Lesson {
@PrimaryGeneratedColumn()
id:number;

@Column()
title:string;

@Column('text')
content:string;

@ManyToOne(()=>Model,(model)=>model.lessons)
model:Model;

}
